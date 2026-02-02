#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import sys
import logging

import argparse
import asyncio

from typing import Literal, Optional

import httpx

logging.basicConfig(
    format="%(asctime)s [%(module)s] - %(levelname)s - %(message)s", level=logging.INFO
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


async def check_consistency(
    base_url: str,
    evc_ids: Optional[list[str]] = None,
    outcome="inconsistent",
    inconsistent_action: Optional[Literal["fix", "redeploy", "disable"]] = None,
) -> dict:
    """Make a request to /telemetry_int/v1/check_consistency."""

    endpoint = f"/telemetry_int/v1/evc/check_consistency?outcome={outcome}"
    if inconsistent_action:
        endpoint = f"{endpoint}&inconsistent_action={inconsistent_action}"
    async with httpx.AsyncClient(base_url=base_url) as client:
        payload = {"evc_ids": evc_ids or []}
        resp = await client.post(endpoint, timeout=20, json=payload)
        try:
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            logger.error(resp.json())
            raise
        return resp.json()


async def check_consistency_cmd(args: argparse.Namespace) -> str:
    """check_consistency cmd.

    If any coroutine fails its exception will be bubbled up.
    """
    evc_ids = [evc_id for evc_id in args.evc_ids.split(",") if evc_id]
    evcs = await check_consistency(
        args.base_url, evc_ids, args.outcome, args.inconsistent_action
    )
    return json.dumps(evcs)


async def main() -> None:
    """Main function."""
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title="commands", dest="command")

    check_parser = subparsers.add_parser("check_consistency", help="Consistency Check")
    check_parser.add_argument(
        "--base_url",
        type=str,
        default="http://localhost:8181/api/kytos",
        help="Kytos-ng API base url",
    )
    check_parser.add_argument(
        "--evc_ids",
        type=str,
        help="INT EVC ids separated by comma to be checked. It will include all if it's empty",
        default="",
    )
    check_parser.add_argument(
        "--outcome",
        type=str,
        help="Outcome filter. 'inconsistent' (default) or 'consistent'",
        default="inconsistent",
    )
    check_parser.add_argument(
        "--inconsistent_action",
        type=str,
        help="Action performed for inconsistent INT EVCs. 'fix', 'redeploy', 'disable' or '' (no operation)",
        default="",
    )

    args = parser.parse_args()

    try:
        if args.command == "check_consistency":
            print(await check_consistency_cmd(args))
    except (httpx.HTTPError, AssertionError) as exc:
        logger.error(f"Error when running '{args.command}': {exc}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
