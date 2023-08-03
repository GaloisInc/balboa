from dataclasses import dataclass
from itertools import chain, product
from typing import Callable, Iterable, List, TypeVar, Union, cast

import pytest
from _pytest.mark.structures import Mark, MarkDecorator

_T = TypeVar("_T")


@dataclass(frozen=True)
class Marked:
    "A parameterized value with associated pytest marks. See `parameterize_test`."
    value: object
    marks: List[Union[Mark, MarkDecorator]]


# TODO: type this better? If it's worth it? We only use this on tests, and we don't call tests,
# anyway.
def parameterize_test(
    **parameters: Iterable[object],
) -> Callable[[_T], _T]:
    """
    Parametrize a test by providing keyword arguments. The test will be run with the cartesian
    product of the parameters. Parameters can be marked with pytest marks. These marks will apply
    to all entries of the product containing that value.
    # Example
    ```python
    @parametrize_test(
        x = [1, 2],
        y = [8, Marked(42, pytest.mark.skip("Skip 42"))],
    )
    # Turns into:
    # test_foo(1, 8)
    # @pytest.mark.skip("Skip 42")
    # test_foo(1, 42)
    # test_foo(2, 8)
    # @pytest.mark.skip("Skip 42")
    # test_foo(2, 42)
    def test_foo(x: int, y: int) -> None:
        assert x == y
    ```
    """
    params = list(parameters.items())
    return cast(
        Callable[[_T], _T],
        pytest.mark.parametrize(
            [k for k, _ in params],
            [
                pytest.param(
                    *[marked.value for marked in entries],
                    marks=list(chain.from_iterable(marked.marks for marked in entries)),
                )
                for entries in product(
                    *[
                        [v if isinstance(v, Marked) else Marked(v, []) for v in l]
                        for _, l in params
                    ]
                )
            ],
        ),
    )
