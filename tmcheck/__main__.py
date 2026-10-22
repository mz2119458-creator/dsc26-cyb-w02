"""CLI entry point: python -m tmcheck MODEL.yaml"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict

from .core import (
    ModelError,
    coverage_gaps,
    load_model,
    policy_findings,
    rank,
    validate,
)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m tmcheck MODEL.yaml", file=sys.stderr)
        return 2

    try:
        model = load_model(argv[1])
    except ModelError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    issues = validate(model)
    gaps = [] if issues else coverage_gaps(model)
    policy = [] if issues else policy_findings(model)
    ranked = rank(model)

    payload = {
        "issues": [asdict(item) for item in issues],
        "gaps": [asdict(item) for item in gaps],
        "policy": [asdict(item) for item in policy],
        "ranked": [asdict(item) for item in ranked],
    }
    print(json.dumps(payload, indent=2))

    if issues or gaps or policy:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
