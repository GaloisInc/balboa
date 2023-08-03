import enum
import json
import os
import platform
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import (
    Callable,
    Dict,
    FrozenSet,
    Generic,
    List,
    Optional,
    Set,
    TypeVar,
    Union,
    cast,
)

import networkx as nx  # type: ignore

import rocky
from rocky.etc.machine import PIPE
from rocky.etc.machine.local import local_machine, local_pkgset_env
from rocky.etc.nix import PkgSet, pkgset

_built_artifacts_lock = Lock()
_built_artifacts: Set["BuildArtifact[Target]"] = set()
_built_llvm_bitcode_lock = Lock()
_built_llvm_bitcode: Dict["Target", Path] = dict()


def all_built_artifacts() -> FrozenSet["BuildArtifact[Target]"]:
    "Return the set of all build artifacts built during this run of Python."
    with _built_artifacts_lock:
        return frozenset(_built_artifacts)


class BuildMode(enum.Enum):
    DEBUG = enum.auto()
    RELEASE = enum.auto()

    def __str__(self) -> str:
        if self == BuildMode.DEBUG:
            return "debug"
        elif self == BuildMode.RELEASE:
            return "release"
        else:
            raise Exception("Unknown build mode")


_cargo_home: Optional[str] = None


def _rocky_stable_root() -> Path:
    if rocky.IS_IN_CI:
        # Sccache uses the absolute path of sources in its cache key. Gitlab CI will change the
        # path where rocky is stored on each CI invocation. To get around this, on CI, we access
        # the rocky repo through a stable symlink
        out = Path.home() / "rocky-ci-stable-symlink"
        if out.exists() and out.readlink() != rocky.ROOT:
            out.unlink()
        if not out.exists():
            out.symlink_to(rocky.ROOT)
        return out
    else:
        return rocky.ROOT


def _cargo_env(target_dir: Path) -> Dict[str, str]:
    global _cargo_home
    out = {
        "CARGO_TARGET_DIR": str(
            _rocky_stable_root() / target_dir.relative_to(rocky.ROOT)
        )
    }
    if rocky.IS_IN_CI:
        key = target_dir.relative_to(rocky.ROOT / "target/nix")
        out["SCCACHE_S3_KEY_PREFIX"] = f"rust-sccache/{key}/"
        if _cargo_home is None:
            renv = local_pkgset_env(_rust_pkgset(llvm_tools=False))
            if "ROCKY_SCCACHE_DATA_DIR" in renv:
                _cargo_home = os.path.join(
                    renv["ROCKY_SCCACHE_DATA_DIR"], "cargo-home", key
                )
            else:
                _cargo_home = ""
        assert _cargo_home is not None
        if _cargo_home != "":
            out["CARGO_HOME"] = _cargo_home
    return out


# Rust uses the same cache for both the nix version of targets and the non-nix version. This can
# cause problems. To fix this, we put the nix artifacts in a separate target directory.
def _cargo_target_dir(for_rust_pkgset: PkgSet, variant: str) -> Path:
    """
    Return the target directory which should be used with Cargo.

    If the `variant` argument is specified, then this function will return a custom subdirectory for
    that variant.
    """
    out = rocky.ROOT / "target/nix" / variant / for_rust_pkgset.instantiated_hash
    if variant is not None:
        out = out / variant
    out.mkdir(exist_ok=True, parents=True)
    return out


def _rust_pkgset(llvm_tools: bool) -> PkgSet:
    """The rust `PkgSet` with sccache enabled if the code is running in CI."""
    return pkgset("rust", dict(enableSccache=rocky.IS_IN_CI, addLLVMTools=llvm_tools))


def _build_command(build_mode: BuildMode, target: "Target") -> List[str]:
    cmd = ["cargo", "build"]
    if build_mode == BuildMode.RELEASE:
        cmd.append("--release")
    cmd.append("-p")
    cmd.append(target.package)
    cmd += target._build_command_target_selection()
    return cmd


_NORMAL_BUILD_VARIANT = "build"


class Target(ABC):
    package: str

    def build(self: "_U", build_mode: BuildMode) -> "BuildArtifact[_U]":
        "Build this Rust target into an executable or dynamic library (depending on the target type)."
        rps = _rust_pkgset(llvm_tools=False)
        target_dir = _cargo_target_dir(rps, _NORMAL_BUILD_VARIANT)
        ba = BuildArtifact(
            target=self,
            build_mode=build_mode,
            path=target_dir / str(build_mode) / self._build_output_path(),
        )
        with _built_artifacts_lock:
            if ba not in _built_artifacts:
                cmd = _build_command(build_mode, self)
                with local_machine() as machine:
                    machine.run(
                        rps,
                        cmd,
                        cwd=_rocky_stable_root(),
                        env=_cargo_env(target_dir),
                    )
                _built_artifacts.add(ba)
        return ba

    def build_llvm_bitcode(self, build_mode: BuildMode) -> Path:
        "Compile and llvm-link a target into an LLVM .bc file."
        with _built_llvm_bitcode_lock:
            if self in _built_llvm_bitcode:
                return _built_llvm_bitcode[self]
            out_path: Optional[Path] = None
            rps = _rust_pkgset(llvm_tools=True)
            target_dir = _cargo_target_dir(rps, "llvm-bc")
            cmd = _build_command(build_mode, self)
            with local_machine() as machine:
                machine.run(
                    rps,
                    cmd,
                    cwd=_rocky_stable_root(),
                    env={
                        "RUSTC_WRAPPER": "rustc-llvm-bitcode-wrapper",
                    }
                    | _cargo_env(target_dir),
                )

                # The path that we compute here is target/.../my-target-name. This path is a hard-link of
                # target/.../my-target-name-SOME_HEX_STRING. The .bc file that contains the LLVM bitcode
                # lives at target/.../my-target-name-SOME_HEX_STRING.bc. To find the .bc file, we first find
                # the unsuffixed path (using our "standard" build_output_path function). Then we find the
                # suffixed path which is a hard link to the standard path. Then we add the ".bc" extension
                # to find the .bc file we're looking for.
                unsuffixed_output = (
                    target_dir / str(build_mode) / self._build_output_path()
                )
                for f in target_dir.glob("**/*"):
                    if str(f) == str(unsuffixed_output):
                        continue
                    if f.samefile(unsuffixed_output):
                        bc = f.with_suffix(".bc")
                        if bc.exists():
                            out_path = bc
                            break
                        bc = bc.with_stem(bc.stem.replace("lib", "", 1))
                        if bc.exists():
                            out_path = bc
                            break
            if out_path is None:
                raise Exception("Unable to find hard link to output")
            else:
                _built_llvm_bitcode[self] = out_path
                return out_path

    def llvm_call_graph(self, build_mode: BuildMode) -> nx.DiGraph:
        """
        Extract the static call graph from LLVM for the target.

        The resulting graph is a directed graph. Nodes are labelled with their demangled function names

        `A -> B` iff A calls B

        Undefined functions point to a special node called `"UNDEFINED"`.
        Functions containing external calls (including dynamic dispatch) point to a special node called `"EXTERNAL"`.
        """
        return _llvm_call_graph(self, build_mode)

    @abstractmethod
    def _build_command_target_selection(self) -> List[str]:
        """
        Beyond the `-p <package name>` what arguments need to be passed to cargo to build this
        target.
        """

    @abstractmethod
    def _build_output_path(self) -> Path:
        """
        After the `/debug` or `/release` part of the path, where does the target's build output
        live.
        """


def _llvm_call_graph(target: Target, build_mode: BuildMode) -> nx.DiGraph:
    from rust_demangler import demangle  # type: ignore

    def try_demangle(x: str) -> str:
        "Try to demangle a rust symbol. Returning the original if demangling fails."
        try:
            return cast(str, demangle(x))
        except:
            return x

    def dealias_llvm_disassembly(input: str) -> str:
        """
        Replace calls to aliased functions in LLVM disassembly with calls to what the alias points
        to.

        Although we've explicitly disabled optimizations in the LLVM bitcode that we compile, the
        bitcode that we use for the Rust standard library has already seen some optimizations.
        In particular, the [MergeFunctions LLVM pass][1] has been applied. This pass uses aliases to
        remove identical functions while having the original names point to the new function.

        Inside [LLVM's CallGraph generation code][2], if a `Call` instruction returns a null result
        to `getCalledFunction()`, then it's assumed to be an "External" call (which is also used to
        denote virtual dispatch). [`getCalledFunction()`][3] invokes `getCalledOperand()` which, for
        a `GlobalAlias`, returns a `GlobalAlias` object, not a `Function` object. As a result,
        (my hypothesis is that) `getCalledFunction()` returns `null` when calling function through
        a `GlobalAlias`.

        This function parses out aliases, and replaces calls to aliases with calls to what the alias
        points to. This means that LLVM will emit a more accurate call graph.

        [1]: https://llvm.org/docs/MergeFunctions.html
        [2]: https://github.com/llvm/llvm-project/blob/1f169a774cb865659cefe085e70a56a884e3711e/llvm/lib/Analysis/CallGraph.cpp#L103
        [3]: https://github.com/llvm/llvm-project/blob/e6d22d0174e09fa01342d9ed1dca47bc1eb58303/llvm/include/llvm/IR/InstrTypes.h#L1396
        """
        # TODO: manipulating the disassembly like this is maybe a little hacky :) But it works for
        # now.
        alias_definition = re.compile(
            r"(@[^ ]+) = internal unnamed_addr alias .+ (@.+)\n"
        )
        alias_graph = nx.DiGraph()
        for match in alias_definition.finditer(input):
            alias_graph.add_edge(match[1], match[2])
        final_names = set(node for node in alias_graph if len(alias_graph[node]) == 0)
        rewrites = []
        for node in alias_graph:
            if node in final_names:
                continue
            new_names = set(nx.descendants(alias_graph, node)) & final_names
            assert len(new_names) == 1
            new_name = list(new_names)[0]
            rewrites.append((node, new_name))
        out_lines = []
        for line in input.split("\n"):
            new_line = line
            if " call " in line:
                for old, new in rewrites:
                    new_line = new_line.replace(old, new)
            out_lines.append(new_line)
        return "\n".join(out_lines)

    with local_machine() as machine:
        rps = _rust_pkgset(llvm_tools=True)
        rustc_sysroot = (
            machine.run(rps, ["rustc", "--print", "sysroot"], stdout=PIPE)
            .stdout.decode("ascii")
            .strip()
        )
        opt_binary_candidates = [
            candidate
            for candidate in machine.run(
                rps, ["find", rustc_sysroot, "-name", "opt"], stdout=PIPE
            )
            .stdout.decode("ascii")
            .strip()
            .split("\n")
            if candidate.strip() != ""
        ]
        if len(opt_binary_candidates) != 1:
            raise Exception(
                f"Could not find a unique 'opt' binary: {repr(opt_binary_candidates)}"
            )
        opt = opt_binary_candidates[0]
        nm = str(Path(opt).parent / "llvm-nm")
        dis = str(Path(opt).parent / "llvm-dis")
        bc = target.build_llvm_bitcode(build_mode)
        # Symbols are prefixed with "_" on the mac.
        maybe_strip_underscore: Callable[[str], str]
        if platform.system() == "Darwin":
            maybe_strip_underscore = lambda x: x[1:] if x[0] == "_" else x
        else:
            maybe_strip_underscore = lambda x: x
        undefined_symbols = set(
            maybe_strip_underscore(line.split()[1])
            for line in machine.run(rps, [nm, "--undefined-only", bc], stdout=PIPE)
            .stdout.decode("ascii")
            .strip()
            .split("\n")
        )
        # We disassemble the llvm bitcode so that we can preprocess it.
        # See the dealias_llvm_disassembly() function above.
        disassembly = machine.run(rps, [dis, bc, "-o", "-"], stdout=PIPE).stdout
        out = machine.run(
            rps,
            [
                opt,
                "--print-callgraph",
                "-o",
                "/dev/null",
                "-",
            ],
            stdout=PIPE,
            stderr=PIPE,
            stdin=None,
            input=dealias_llvm_disassembly(disassembly.decode("ascii")).encode("ascii"),
        )
        # The actual output is written to stderr, not stdout.
        cg = nx.DiGraph()
        cg.add_node("EXTERNAL")
        cg.add_node("UNDEFINED")
        for sym in undefined_symbols:
            cg.add_node(sym)
            cg.add_edge(sym, "UNDEFINED")
        lines = out.stderr.decode("ascii").strip().split("\n")
        current_node: Optional[str] = None
        for line in lines:
            if line.startswith("Call graph node "):
                if "<null function>" in line:
                    current_node = "<null function>"
                else:
                    current_node = try_demangle(line.split("'")[1].split("'")[0])
                cg.add_node(current_node)
            elif line.startswith("  CS"):
                assert current_node is not None
                if current_node in undefined_symbols:
                    continue
                if "calls external node" in line:
                    cg.add_edge(current_node, "EXTERNAL")
                    continue
                assert "calls function" in line
                callee = try_demangle(line.split("'")[1].split("'")[0])
                cg.add_node(callee)
                cg.add_edge(current_node, callee)
            else:
                # Otherwise, reset the state and ignore the line
                current_node = None
        return cg


@dataclass(frozen=True)
class ExecutableTarget(Target):
    """A Rust target which results in an executable binary."""

    name: str
    package: str
    is_example: bool

    def _build_command_target_selection(self) -> List[str]:
        return ["--example" if self.is_example else "--bin", self.name]

    def _build_output_path(self) -> Path:
        if self.is_example:
            return Path("examples") / self.name
        else:
            return Path(self.name)


@dataclass(frozen=True)
class CDylibTarget(Target):
    """A Rust target which results in a `cdylib` crate type."""

    package: str

    def _build_command_target_selection(self) -> List[str]:
        return []

    def _build_output_path(self) -> Path:
        return Path(f"lib{self.package.replace('-', '_')}").with_suffix(
            ".dylib" if platform.system() == "Darwin" else ".so"
        )


_T = TypeVar("_T", bound=Target, covariant=True)
_U = TypeVar("_U", bound=Target)


@dataclass(frozen=True)
class BuildArtifact(Generic[_T]):
    """A built Rust target."""

    target: _T
    build_mode: BuildMode
    path: Path


_lock = Lock()
_initialized = False
_executable_target_cache: Dict[str, ExecutableTarget] = dict()
_cdylib_target_cache: Dict[str, CDylibTarget] = dict()


def _initialize_cache() -> None:
    global _initialized
    # There's no need to hold the lock _after_ the initialize function has been called,
    # since the dicts become read-only at that point.
    with _lock:
        if _initialized:
            return
        with local_machine() as machine:
            for pkg in json.loads(
                machine.run(
                    _rust_pkgset(llvm_tools=False),
                    [
                        "cargo",
                        "metadata",
                        "--no-deps",
                        "--format-version",
                        "1",
                    ],
                    stdout=PIPE,
                    cwd=_rocky_stable_root(),
                ).stdout
            )["packages"]:
                for target in pkg["targets"]:
                    assert len(target["crate_types"]) == 1
                    if "custom-build" in target["kind"] or "bench" in target["kind"]:
                        # Exclude build scripts and benchmarks.
                        continue
                    if target["crate_types"][0] == "bin":
                        _executable_target_cache[target["name"]] = ExecutableTarget(
                            name=target["name"],
                            package=pkg["name"],
                            is_example="example" in target["kind"],
                        )
                    elif target["crate_types"][0] == "cdylib":
                        assert target["name"] == pkg["name"]
                        _cdylib_target_cache[target["name"]] = CDylibTarget(
                            package=pkg["name"],
                        )
                    else:
                        # Otherwise, ignore the target
                        continue
        _initialized = True


def executable_target(name: str) -> ExecutableTarget:
    """
    Return an `ExecutableTarget` which produces an executable of the given `name`, raising an
    Exception if one doesn't exist.
    """
    _initialize_cache()
    if name not in _executable_target_cache:
        raise Exception(f"Unknown executable target: {name}")
    return _executable_target_cache[name]


def cdylib_target(name: str) -> CDylibTarget:
    """
    Return an `CDylibTarget` which produces a cdylib of the given `name`, raising an
    Exception if one doesn't exist.
    """
    _initialize_cache()
    if name not in _cdylib_target_cache:
        raise Exception(f"Unknown cdylib target: {name}")
    return _cdylib_target_cache[name]


def all_targets() -> FrozenSet[Target]:
    "Return a list of all possible `Target`s"
    _initialize_cache()
    return frozenset(_cdylib_target_cache.values()) | frozenset(
        _executable_target_cache.values()
    )


# CI Helper functions


def ci_helper_compile_rust(build_mode: BuildMode) -> None:
    "Compile all targets in the codebase."
    rps = _rust_pkgset(llvm_tools=False)
    target_dir = _cargo_target_dir(rps, _NORMAL_BUILD_VARIANT)
    with local_machine() as machine:
        machine.run(
            rps,
            [
                "cargo",
                "build",
                "--workspace",
                "--all-targets",
            ]
            + (["--release"] if build_mode == BuildMode.RELEASE else []),
            cwd=_rocky_stable_root(),
            env=_cargo_env(target_dir),
        )
        # cargo build --workspace --all-targets doesn't build libraries the same way as cargo build -p <>
        for target in all_targets():
            target.build(build_mode)


def ci_helper_test_rust() -> None:
    "Run the rust tests."
    rps = _rust_pkgset(llvm_tools=False)
    target_dir = _cargo_target_dir(rps, _NORMAL_BUILD_VARIANT)
    with local_machine() as machine:
        machine.run(
            rps,
            [
                "cargo",
                "test",
                "--workspace",
            ],
            cwd=_rocky_stable_root(),
            env=_cargo_env(target_dir),
        )
