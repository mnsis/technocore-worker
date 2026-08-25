from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

from worker.identity import generate_identity, load_identity, public_did
from worker.service import run_forever
from worker.state import State


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Minimal signed Technocore task worker")
    subparsers = result.add_subparsers(dest="command", required=True)
    init = subparsers.add_parser("init")
    init.add_argument("--identity", type=Path, required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--identity", type=Path, default=None)
    run.add_argument("--database", type=Path, default=None)
    run.add_argument("--inbox", default=None)
    show = subparsers.add_parser("did")
    show.add_argument("--identity", type=Path, required=True)
    web = subparsers.add_parser("web", help="run the loopback-only browser prototype")
    web.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1", "::1", "localhost"])
    web.add_argument("--port", type=int, default=18787)
    web.add_argument("--public-origin", default=None)
    return result


def main() -> None:
    args = parser().parse_args()
    if args.command == "init":
        print(generate_identity(args.identity))
        return
    if args.command == "did":
        print(public_did(load_identity(args.identity)))
        return
    if args.command == "web":
        from worker.webapp import serve

        serve(args.host, args.port, public_origin=args.public_origin)
        return
    identity = args.identity or Path(os.environ["TC_WORKER_IDENTITY"])
    database = args.database or Path(os.environ["TC_WORKER_DATABASE"])
    inbox = args.inbox or os.environ["TC_WORKER_INBOX"]
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    run_forever(inbox=inbox, key=load_identity(identity), state=State(database))
