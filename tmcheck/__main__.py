"""Command line: python -m tmcheck MODEL.yaml

Print one JSON object with the keys "issues", "gaps", "policy" and "ranked" (each a list of
objects with the dataclass fields, for example {"ref": "f01", "category": "T"}).
Exit code 2 if the file cannot be loaded, 1 if there are any issues, gaps or policy findings,
otherwise 0. If there are structural issues you may leave "gaps" and "policy" empty.
"""
import sys


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m tmcheck MODEL.yaml", file=sys.stderr)
        return 2
    path = argv[0]
    raise NotImplementedError


if __name__ == "__main__":
    raise SystemExit(main())
