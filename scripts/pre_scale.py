#!/usr/bin/env python3
"""
Pre-scale zuultimate pods for predictable traffic events.
Usage: python pre_scale.py --event "Super Bowl" --target-rps 50000 --duration-hours 4
"""
import argparse
import json
import subprocess
import sys
from math import ceil
from datetime import datetime, timedelta

RPS_PER_POD = 800
SAFETY_MARGIN = 1.5


def calculate_pod_count(target_rps: int) -> int:
    """Calculate the number of pods needed to handle a target RPS with safety margin."""
    return ceil(target_rps / RPS_PER_POD * SAFETY_MARGIN)


def generate_commands(
    deployment: str,
    namespace: str,
    pod_count: int,
    duration_hours: float,
    event_name: str,
) -> list[str]:
    """Generate kubectl commands for pre-scaling and scheduled revert.

    Returns a list of shell commands to execute in sequence.
    """
    revert_time = datetime.utcnow() + timedelta(hours=duration_hours)
    revert_iso = revert_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    commands = [
        # Annotate the deployment with event metadata
        (
            f'kubectl annotate deployment {deployment} -n {namespace} '
            f'--overwrite pre-scale/event="{event_name}" '
            f'pre-scale/target-rps="{pod_count * RPS_PER_POD}" '
            f'pre-scale/revert-at="{revert_iso}"'
        ),
        # Scale to target
        f"kubectl scale deployment {deployment} -n {namespace} --replicas={pod_count}",
        # Schedule revert (at command — works on Linux)
        (
            f'echo "kubectl scale deployment {deployment} -n {namespace} '
            f'--replicas=10" | at {revert_time.strftime("%H:%M %Y-%m-%d")}'
        ),
    ]
    return commands


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pre-scale zuultimate pods for predictable traffic events."
    )
    parser.add_argument("--event", required=True, help="Name of the traffic event")
    parser.add_argument(
        "--target-rps", type=int, required=True, help="Target requests per second"
    )
    parser.add_argument(
        "--duration-hours",
        type=float,
        default=4.0,
        help="Duration in hours before reverting (default: 4)",
    )
    parser.add_argument(
        "--deployment",
        default="zuultimate-auth",
        help="Deployment name (default: zuultimate-auth)",
    )
    parser.add_argument(
        "--namespace",
        default="zuultimate",
        help="Kubernetes namespace (default: zuultimate)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without executing",
    )

    args = parser.parse_args()

    pod_count = calculate_pod_count(args.target_rps)
    print(f"Event: {args.event}")
    print(f"Target RPS: {args.target_rps}")
    print(f"Pod count: {pod_count} (safety margin: {SAFETY_MARGIN}x)")
    print(f"Duration: {args.duration_hours}h")
    print()

    commands = generate_commands(
        args.deployment, args.namespace, pod_count, args.duration_hours, args.event
    )

    for cmd in commands:
        print(f"  $ {cmd}")
        if not args.dry_run:
            try:
                subprocess.run(cmd, shell=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"  ERROR: {e}", file=sys.stderr)
                sys.exit(1)

    if args.dry_run:
        print("\n(dry run — no commands executed)")


if __name__ == "__main__":
    main()
