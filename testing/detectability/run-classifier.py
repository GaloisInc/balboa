# type: ignore
# We don't mypy check this file, since it has large dependencies that we don't want to have to
# install just to check things with mypy.
# For the same reason, this file is invoked as a standalone binary, and not imported into the rest
# of the rocky python code.

import csv
import json
import subprocess
import sys
import warnings
from io import StringIO
from pathlib import Path

IGNORE_TCPTRACE_KEYS = [
    # We delete the connection number because that's related to the order in the dataset.
    "conn_#",
    "last_packet",
    "first_packet",
    "port_a",
    "port_b",
]


def parse_flows(paths):
    raw = subprocess.run(
        ["tcptrace", "-n", "-l", "--csv"] + [str(path) for path in paths],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
    ).stdout.decode("ascii")
    # Strip out the comments (lines which start with '#')
    raw_lines = raw.splitlines()
    raw = "\n".join(line for line in raw_lines if line != "" and line[0] != "#")
    with StringIO(raw) as f:
        reader = csv.DictReader(f)
        for row in reader:
            out = dict()
            for k, v in row.items():
                k = k.strip()
                if k == "":
                    continue
                if v is None:
                    continue
                v = v.strip()
                if "/" in v or v in ["Y", "N"]:
                    # TODO: do we care about these features.
                    continue
                if v == "NA" or v == "":
                    out[k] = None
                elif "." in v:
                    try:
                        out[k] = float(v)
                    except ValueError:
                        # It's probably an IP address
                        continue
                else:
                    out[k] = int(v)
            yield out


if __name__ == "__main__":
    # Import these under the __name__ umbrella, to silence the pdoc warnings about missing imports
    # (since it doesn't run with the classifier libraries installed).
    import numpy as np
    import pandas as pd
    from joblib import parallel_backend
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.exceptions import UndefinedMetricWarning
    from sklearn.model_selection import RepeatedStratifiedKFold, cross_validate

    warnings.filterwarnings("error")

    # This file shouldn't be invoked directly, so we won't worry about a help page, or a fancy CLI
    # here.
    captures = Path(sys.argv[1])
    variants = list(filter(lambda entry: entry.is_dir(), captures.iterdir()))
    if len(variants) != 2:
        raise Exception("You need to have exactly 2 variants to classify!")
    variant_names = sorted([v.name for v in variants])
    variant_key = variant_names[0]
    for v in variant_names:
        if "enabled" in v.lower():
            variant_key = v
    if len(set(len(list(v.iterdir())) for v in variants)) != 1:
        # TODO: will this actually skew anything?
        raise Exception("Not all variants have the same number of packet captures.")
    flows = []
    all_columns = set()
    for variant in variants:
        for row in parse_flows(list(variant.glob("*.pcap"))):
            row[variant_key] = variant.name == variant_key
            flows.append(row)
            for k in row.keys():
                all_columns.add(k)
    # Delete all columns we explicitly ignore
    delete_cols = set(IGNORE_TCPTRACE_KEYS)
    # or that aren't numeric, or aren't present in all rows
    for flow in flows:
        for k, v in flow.items():
            if k == variant_key:
                continue
            if type(v) not in (int, float):
                delete_cols.add(k)
        for c in all_columns:
            if c not in flow and c != variant_key:
                delete_cols.add(c)
    print(f"Deleting columns {delete_cols}", file=sys.stderr)
    for flow in flows:
        for col in delete_cols:
            if col in flow:
                del flow[col]
    df = pd.DataFrame(flows)
    data_cols = [x for x in df.columns if x != variant_key]
    target_cols = [variant_key]
    X = df[data_cols]
    y = np.ravel(df[target_cols])
    with parallel_backend("multiprocessing"):
        scores = cross_validate(
            RandomForestClassifier(),
            X,
            y,
            # n_splits=10
            cv=RepeatedStratifiedKFold(n_splits=5, n_repeats=50),
            scoring=["accuracy", "precision", "recall"],
            return_estimator=True,
            n_jobs=-1,
        )
    estimators = scores["estimator"]
    del scores["estimator"]
    out = {k: list(v) for k, v in scores.items()}
    out["feature_importances"] = [
        dict(zip(X.columns, estimator.feature_importances_)) for estimator in estimators
    ]
    sys.stdout.write(json.dumps(out))
