"""
draugr_scheduler.py — Scheduled / automated scanning for Draugr.

Runs scans on a configurable schedule, compares against the previous scan,
writes diff and trend reports, and fires alerts.

Usage (as a background service):
    python draugr_scheduler.py --config scheduler.json

Or from within draugr.py:
    from draugr_scheduler import SchedulerConfig, DraugrScheduler
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


_DEFAULT_SCHEDULER_CONFIG: Dict[str, Any] = {
    "enabled": False,
    "interval_hours": 24,
    "jobs": [
        # Each job is a dict matching draugr CLI args
        # {
        #   "name": "workstation-fleet",
        #   "input": "C:/scans/hapy_software_agent_1.csv",
        #   "output": "C:/draugr_results/workstation-fleet",
        #   "kev": "",
        #   "api_key": "",
        #   "otx_key": "",
        #   "diff": true,        # auto-diff against previous scan
        #   "alert": true,       # fire alerts after scan
        # }
    ],
    "draugr_script": "",   # path to draugr.py; defaults to same directory
    "log_file": "draugr_scheduler.log",
}


def _scheduler_config_path() -> Path:
    return Path(os.path.dirname(os.path.abspath(__file__))) / "draugr_scheduler.json"


def load_scheduler_config() -> Dict[str, Any]:
    path = _scheduler_config_path()
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            merged = dict(_DEFAULT_SCHEDULER_CONFIG)
            merged.update(cfg)
            return merged
        except (json.JSONDecodeError, OSError):
            pass
    return dict(_DEFAULT_SCHEDULER_CONFIG)


def save_scheduler_config(cfg: Dict[str, Any]) -> None:
    with open(_scheduler_config_path(), "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def create_default_scheduler_config() -> Path:
    path = _scheduler_config_path()
    if not path.exists():
        save_scheduler_config(_DEFAULT_SCHEDULER_CONFIG)
    return path


class DraugrScheduler:
    """
    Lightweight scheduler that invokes draugr's headless CLI on a regular interval.

    Each job runs draugr --scan <input> --output <output> [options].
    After each scan, if diff=True, it runs a delta comparison against the
    previous CSV in the output directory.
    """

    def __init__(self, cfg: Optional[Dict[str, Any]] = None):
        self.cfg = cfg or load_scheduler_config()
        self._log_path = Path(self.cfg.get("log_file", "draugr_scheduler.log"))
        self._draugr   = self._find_draugr()
        self._running  = False

    def _find_draugr(self) -> str:
        """Locate the draugr.py script."""
        explicit = self.cfg.get("draugr_script", "")
        if explicit and Path(explicit).exists():
            return explicit
        here = Path(os.path.dirname(os.path.abspath(__file__))) / "draugr.py"
        if here.exists():
            return str(here)
        return "draugr.py"

    def _log(self, msg: str) -> None:
        import datetime
        line = f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
        print(line)
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass

    def _find_previous_csv(self, output_dir: str, job_name: str) -> Optional[str]:
        """
        Find the most recently written CSV in the output/reports directory
        to use as the 'previous' scan for diffing.
        """
        report_dir = Path(output_dir) / "reports"
        if not report_dir.exists():
            return None
        csvs = sorted(report_dir.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
        # Skip the one we just wrote (most recent) — return the second most recent
        if len(csvs) >= 2:
            return str(csvs[1])
        return None

    def _run_job(self, job: Dict[str, Any]) -> bool:
        """Run a single scan job. Returns True on success."""
        name    = job.get("name", "unnamed")
        inp     = job.get("input", "")
        out     = job.get("output", "")
        do_diff = job.get("diff", True)

        if not inp or not Path(inp).exists():
            self._log(f"  [{name}] SKIP — input file not found: {inp}")
            return False
        if not out:
            self._log(f"  [{name}] SKIP — no output directory configured")
            return False

        self._log(f"  [{name}] Starting scan: {inp} → {out}")

        # Find previous CSV before running (new scan will add one)
        prev_csv = self._find_previous_csv(out, name) if do_diff else None

        cmd = [sys.executable, self._draugr, "--scan", inp, "--output", out]
        if job.get("kev"):
            cmd += ["--kev", job["kev"]]
        if job.get("api_key"):
            cmd += ["--api-key", job["api_key"]]
        if job.get("otx_key"):
            cmd += ["--otx-key", job["otx_key"]]
        if job.get("resources"):
            cmd += ["--resources", job["resources"]]

        # If diff and we have a previous CSV, pass it
        if do_diff and prev_csv:
            cmd += ["--diff", prev_csv]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,   # 1 hour max per scan
            )
            if result.returncode == 0:
                self._log(f"  [{name}] Scan complete")
                return True
            else:
                self._log(f"  [{name}] Scan FAILED (exit {result.returncode}): {result.stderr[:200]}")
                return False
        except subprocess.TimeoutExpired:
            self._log(f"  [{name}] TIMEOUT after 1 hour")
            return False
        except Exception as e:
            self._log(f"  [{name}] ERROR: {e}")
            return False

    def run_once(self) -> Dict[str, int]:
        """Run all configured jobs once. Returns {success: n, failed: n}."""
        jobs = self.cfg.get("jobs", [])
        if not jobs:
            self._log("No jobs configured. Edit draugr_scheduler.json to add scan jobs.")
            return {"success": 0, "failed": 0}

        success = 0
        failed  = 0
        self._log(f"Running {len(jobs)} scheduled job(s)...")
        for job in jobs:
            if self._run_job(job):
                success += 1
            else:
                failed += 1
        self._log(f"Batch complete: {success} success, {failed} failed")
        return {"success": success, "failed": failed}

    def run_forever(self) -> None:
        """
        Run the scheduler loop indefinitely at the configured interval.
        Ctrl+C / SIGTERM stops it gracefully.
        """
        interval_s = float(self.cfg.get("interval_hours", 24)) * 3600
        self._running = True
        self._log(f"Draugr scheduler started — interval: {self.cfg.get('interval_hours',24)}h")

        while self._running:
            self.run_once()
            if not self._running:
                break
            next_run = time.time() + interval_s
            import datetime
            self._log(f"Next run: {datetime.datetime.fromtimestamp(next_run):%Y-%m-%d %H:%M:%S}")
            try:
                time.sleep(interval_s)
            except (KeyboardInterrupt, SystemExit):
                break

        self._log("Scheduler stopped.")

    def stop(self) -> None:
        self._running = False


def _scheduler_main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        prog="draugr_scheduler",
        description="Draugr automated scan scheduler",
    )
    parser.add_argument("--config", default="", help="Path to scheduler JSON config")
    parser.add_argument("--once",   action="store_true", help="Run all jobs once and exit")
    parser.add_argument("--init",   action="store_true", help="Create a default config file and exit")
    args = parser.parse_args()

    if args.init:
        path = create_default_scheduler_config()
        print(f"Default scheduler config created: {path}")
        print("Edit it to configure scan jobs, then run without --init to start scheduling.")
        return

    cfg = None
    if args.config and Path(args.config).exists():
        with open(args.config, "r", encoding="utf-8") as f:
            cfg = json.load(f)

    scheduler = DraugrScheduler(cfg)

    if args.once:
        results = scheduler.run_once()
        sys.exit(0 if results["failed"] == 0 else 1)
    else:
        try:
            scheduler.run_forever()
        except KeyboardInterrupt:
            scheduler.stop()


if __name__ == "__main__":
    _scheduler_main()
