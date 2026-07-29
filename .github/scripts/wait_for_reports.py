#!/usr/bin/env python3
"""Wait for queued scanner analyses and refresh their JSON reports in place."""

import argparse
import json
import logging
import os
import time
from pathlib import Path

import requests

log = logging.getLogger("honeypot.wait_reports")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

PENDING_STATUSES = {"queued", "pending", "in_queue", "in_progress", "timeout"}


def _pending(result: dict, identifier: str) -> bool:
    status = str(result.get("status", "")).lower()
    return bool(result.get(identifier)) and (
        status in PENDING_STATUSES or (not status and not result.get("known", False))
    )


def _poll_virustotal(result: dict, key: str) -> dict | None:
    response = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{result['analysis_id']}",
        headers={"x-apikey": key},
        timeout=30,
    )
    if response.status_code != 200:
        log.warning("VirusTotal poll returned HTTP %s", response.status_code)
        return None
    attributes = response.json().get("data", {}).get("attributes", {})
    status = attributes.get("status", "queued")
    if status != "completed":
        result["status"] = status
        return None
    stats = attributes.get("stats", {})
    return {
        **result,
        "status": "completed",
        "positives": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "total": sum(stats.values()),
        "stats": stats,
        "_ok": True,
    }


def _poll_hybrid_analysis(result: dict, key: str) -> dict | None:
    response = requests.get(
        f"https://hybrid-analysis.com/api/v2/report/{result['job_id']}/summary",
        headers={
            "api-key": key,
            "User-Agent": "Falcon Sandbox",
            "accept": "application/json",
        },
        timeout=30,
    )
    if response.status_code == 404:
        result["status"] = "queued"
        return None
    if response.status_code != 200:
        log.warning("Hybrid Analysis poll returned HTTP %s", response.status_code)
        return None
    data = response.json()
    state = data.get("state", "")
    if state in ("", "IN_QUEUE", "IN_PROGRESS"):
        result["status"] = state.lower() or "queued"
        return None
    if state == "ERROR":
        return {
            **result,
            "status": "failed",
            "error": data.get("error_message", "sandbox analysis errored"),
            "_ok": False,
        }
    return {
        **result,
        "status": "completed",
        "verdict": data.get("verdict"),
        "threat_score": data.get("threat_score"),
        "threat_level": data.get("threat_level_human"),
        "av_detect": data.get("av_detect"),
        "_ok": True,
    }


def _poll_malwarebazaar(result: dict, key: str) -> dict | None:
    response = requests.post(
        "https://mb-api.abuse.ch/api/v1/",
        headers={"Auth-Key": key},
        data={"query": "get_info", "hash": result["sha256"]},
        timeout=30,
    )
    if response.status_code != 200:
        log.warning("MalwareBazaar poll returned HTTP %s", response.status_code)
        return None
    data = response.json()
    if data.get("query_status") != "ok" or not data.get("data"):
        result["status"] = "queued"
        return None
    item = data["data"][0]
    return {
        **result,
        "status": "completed",
        "known": True,
        "signature": item.get("signature"),
        "file_type": item.get("file_type"),
        "tags": item.get("tags", []),
        "first_seen": item.get("first_seen"),
        "reporter": item.get("reporter"),
        "_ok": True,
    }


def _poll_metadefender(result: dict, key: str) -> dict | None:
    response = requests.get(
        f"https://api.metadefender.com/v4/file/{result['data_id']}",
        headers={"apikey": key},
        timeout=30,
    )
    if response.status_code != 200:
        log.warning("MetaDefender poll returned HTTP %s", response.status_code)
        return None
    scan = response.json().get("scan_results", {})
    progress = scan.get("progress_percentage", 0)
    if progress != 100:
        result["status"] = "in_progress" if progress else "queued"
        result["progress_percentage"] = progress
        return None
    return {
        **result,
        "status": "completed",
        "positives": scan.get("total_detected_avs", 0),
        "total": scan.get("total_avs", 0),
        "scan_result": scan.get("scan_all_result_a", ""),
        "progress_percentage": 100,
        "_ok": True,
    }


def refresh_report(path: Path) -> int:
    report = json.loads(path.read_text())
    results = report.get("results", {})
    pending = 0
    changed = False

    scanners = (
        ("VirusTotalScanner", "analysis_id", "VT_API_KEY", _poll_virustotal),
        ("MalwareBazaarScanner", "sha256", "MALWAREBAZAAR_API_KEY", _poll_malwarebazaar),
        ("HybridAnalysisScanner", "job_id", "HYBRID_ANALYSIS_KEY", _poll_hybrid_analysis),
        ("MetaDefenderScanner", "data_id", "METADEFENDER_API_KEY", _poll_metadefender),
    )
    for name, identifier, env_name, poller in scanners:
        result = results.get(name)
        if not isinstance(result, dict) or not _pending(result, identifier):
            continue
        key = os.environ.get(env_name, "")
        if not key:
            log.warning("%s remains queued; %s is unavailable", name, env_name)
            pending += 1
            continue
        try:
            completed = poller(result, key)
        except (requests.RequestException, ValueError) as exc:
            log.warning("%s poll failed: %s", name, exc)
            pending += 1
            continue
        changed = True
        if completed is None:
            pending += 1
        else:
            results[name] = completed
            log.info("%s completed for %s", name, report.get("filename", path.name))

    if changed:
        path.write_text(json.dumps(report, indent=2) + "\n")
    return pending


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", default="reports/scanner/")
    parser.add_argument(
        "--newer-than",
        help="Only refresh reports modified after this marker file.",
    )
    parser.add_argument("--timeout-seconds", type=int, default=1200)
    parser.add_argument("--interval-seconds", type=int, default=30)
    args = parser.parse_args()

    report_dir = Path(args.report_dir)
    minimum_mtime = Path(args.newer_than).stat().st_mtime if args.newer_than else 0
    deadline = time.monotonic() + max(0, args.timeout_seconds)
    while True:
        paths = sorted(
            path for path in report_dir.glob("*.json")
            if path.stat().st_mtime >= minimum_mtime
        )
        pending = sum(refresh_report(path) for path in paths)
        if pending == 0:
            log.info("All supported queued analyses reached a terminal state.")
            return 0
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            log.warning(
                "%d queued analysis result(s) remain after %d seconds; "
                "the report will mark them as pending.",
                pending,
                args.timeout_seconds,
            )
            return 0
        delay = min(args.interval_seconds, remaining)
        log.info("Waiting %.0f seconds for %d queued analysis result(s)...", delay, pending)
        time.sleep(delay)


if __name__ == "__main__":
    raise SystemExit(main())
