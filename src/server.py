"""Serve the local, pre-recorded reconnaissance report with Waitress."""

import argparse

from waitress import serve

from src.web import app


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the recorded reconnaissance report.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535.")
    serve(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
