#!/usr/bin/env python3
"""
hoppin_admin.py - review abuse reports and suspend numbers, on the relay.

    sudo /opt/hoppin/venv/bin/python /opt/hoppin/hoppin_admin.py reports --since 24h
    sudo /opt/hoppin/venv/bin/python /opt/hoppin/hoppin_admin.py ban +351912345678 spam links
    sudo /opt/hoppin/venv/bin/python /opt/hoppin/hoppin_admin.py unban +351912345678
    sudo /opt/hoppin/venv/bin/python /opt/hoppin/hoppin_admin.py banned

It lives next to bootstrap.py so it parses the ban file with the relay's own
code. Files come from --reports / --banlist, else HOPPIN_REPORTS /
HOPPIN_BANLIST in the environment, else whatever hoppin-bootstrap.service sets,
else the relay's defaults.

The running relay notices ban file edits within a few seconds; no restart.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Run as root from the relay's directory: don't leave root-owned __pycache__
# files behind in it.
sys.dont_write_bytecode = True

import bootstrap  # noqa: E402

SERVICE = "hoppin-bootstrap"

_service_env: Optional[Dict[str, str]] = None


def service_environment() -> Dict[str, str]:
    """The Environment= lines of the relay's systemd unit, if there is one.

    `sudo` doesn't carry the service's environment, so without this every
    command would need the paths spelled out.
    """
    global _service_env
    if _service_env is not None:
        return _service_env
    _service_env = {}
    try:
        out = subprocess.run(
            ["systemctl", "show", SERVICE, "--property=Environment", "--value"],
            capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return _service_env
    if out.returncode != 0:
        return _service_env
    try:
        tokens = shlex.split(out.stdout)
    except ValueError:
        return _service_env
    for token in tokens:
        key, sep, value = token.partition("=")
        if sep:
            _service_env[key] = value
    return _service_env


def resolve_path(flag: Optional[str], var: str, default: str) -> str:
    if flag:
        return flag
    if os.environ.get(var):
        return os.environ[var]
    return service_environment().get(var) or default


def fail(message: str, code: int = 1) -> int:
    print("hoppin_admin: " + message, file=sys.stderr)
    return code


def safe(text: Any) -> str:
    """Report text is written by strangers: never let it drive the terminal."""
    s = str(text)
    return "".join(ch if ch.isprintable() else "\\x%02x" % ord(ch) if ord(ch) < 0x100
                   else "\\u%04x" % ord(ch) for ch in s)


def when(epoch: Any) -> str:
    try:
        return datetime.datetime.fromtimestamp(
            int(epoch), datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        return "?"


_DURATION_RE = re.compile(r"^(\d+)([smhdw])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 7 * 86400}


def parse_duration(value: str) -> int:
    match = _DURATION_RE.match(value.strip().lower())
    if not match:
        raise argparse.ArgumentTypeError(
            "expected a duration like 30m, 24h or 7d, got %r" % value)
    return int(match.group(1)) * _UNITS[match.group(2)]


def phone_arg(value: str) -> str:
    value = value.strip()
    if not bootstrap.is_valid_e164(value):
        raise argparse.ArgumentTypeError(
            "%r is not an E.164 number (like +351912345678)" % value)
    return value


# ---------------------------------------------------------------------------
# Ban file
# ---------------------------------------------------------------------------

def read_banfile(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def write_banfile(path: str, text: str) -> None:
    """Atomic replace that keeps the file's owner, group and mode.

    The relay reads this file as user `hoppin`, so a rewrite that came out
    root:root 600 would silently freeze the list it enforces. A new file is
    created 640, group `hoppin` when that group exists.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    try:
        st: Optional[os.stat_result] = os.stat(path)
    except FileNotFoundError:
        st = None

    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".",
                               suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        if st is not None:
            os.chmod(tmp, stat.S_IMODE(st.st_mode))
            mine = os.stat(tmp)
            if (mine.st_uid, mine.st_gid) != (st.st_uid, st.st_gid):
                os.chown(tmp, st.st_uid, st.st_gid)
        else:
            os.chmod(tmp, 0o640)
            if os.geteuid() == 0:
                try:
                    import grp
                    os.chown(tmp, 0, grp.getgrnam("hoppin").gr_gid)
                except (ImportError, KeyError):
                    pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        dfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def ban(path: str, phone: str, note: str, today: Optional[str] = None) -> bool:
    """Adds `phone`. False if it was already there (the file is untouched)."""
    text = read_banfile(path)
    if phone in bootstrap.parse_banlist(text):
        return False
    today = today or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    note = " ".join(note.split())        # one line, whatever was typed
    line = "%s  %s %s" % (phone, today, note) if note else "%s  %s" % (phone, today)
    if text and not text.endswith("\n"):
        text += "\n"
    write_banfile(path, text + line.rstrip() + "\n")
    return True


def unban(path: str, phone: str) -> bool:
    """Removes every line for `phone`. False if it wasn't there."""
    text = read_banfile(path)
    kept: List[str] = []
    removed = False
    for line in text.splitlines(keepends=True):
        parts = line.split(None, 1)
        if parts and parts[0] == phone:
            removed = True
            continue
        kept.append(line)
    if removed:
        write_banfile(path, "".join(kept))
    return removed


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def load_reports(path: str) -> Tuple[List[Dict[str, Any]], int]:
    """(reports, unreadable line count). Raises OSError if the file can't be opened."""
    reports: List[Dict[str, Any]] = []
    bad = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError:
                bad += 1
                continue
            if not isinstance(record, dict) or not isinstance(record.get("at"), int):
                bad += 1
                continue
            reports.append(record)
    return reports, bad


def format_report(record: Dict[str, Any], banned: Dict[str, str],
                  show_evidence: bool) -> str:
    reported = safe(record.get("reportedPhone", "?"))
    evidence = record.get("evidence") if isinstance(record.get("evidence"), list) else []
    lines = [
        when(record.get("at")),
        "  reported  %s%s" % (reported, "  (suspended)" if reported in banned else ""),
        "  reporter  %s" % safe(record.get("reporter", "?")),
        "  reason    %s" % safe(record.get("reason", "")),
        "  evidence  %d message(s)" % len(evidence),
    ]
    if show_evidence:
        for item in evidence:
            if isinstance(item, dict):
                lines.append("    [%s] %s" % (when(item.get("timestamp")),
                                              safe(item.get("text", ""))))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_reports(args: argparse.Namespace) -> int:
    try:
        reports, bad = load_reports(args.reports)
    except FileNotFoundError:
        print("No reports yet (%s does not exist)." % args.reports)
        return 0
    except OSError as exc:
        return fail("cannot read %s: %s (run it with sudo)" % (args.reports, exc.strerror))

    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    if args.since is not None:
        reports = [r for r in reports if r["at"] >= now - args.since]
    reports.sort(key=lambda r: r["at"], reverse=True)

    try:
        banned = bootstrap.parse_banlist(read_banfile(args.banlist))
    except OSError:
        banned = {}

    scope = " in the last %s" % args.since_text if args.since is not None else ""
    if not reports:
        print("No reports%s." % scope)
    else:
        print("%d report(s)%s, newest first:" % (len(reports), scope))
        for record in reports:
            print()
            print(format_report(record, banned, args.evidence))
    if bad:
        print("\n(%d unreadable line(s) in %s skipped)" % (bad, args.reports),
              file=sys.stderr)
    return 0


def cmd_ban(args: argparse.Namespace) -> int:
    try:
        added = ban(args.banlist, args.phone, " ".join(args.note))
    except OSError as exc:
        return fail("cannot update %s: %s (run it with sudo)" % (args.banlist, exc.strerror))
    if not added:
        print("%s is already suspended." % args.phone)
        return 0
    print("Suspended %s. The relay applies it within a few seconds." % args.phone)
    return 0


def cmd_unban(args: argparse.Namespace) -> int:
    try:
        removed = unban(args.banlist, args.phone)
    except OSError as exc:
        return fail("cannot update %s: %s (run it with sudo)" % (args.banlist, exc.strerror))
    if not removed:
        print("%s is not suspended." % args.phone)
        return 0
    print("Unsuspended %s. The relay applies it within a few seconds." % args.phone)
    return 0


def cmd_banned(args: argparse.Namespace) -> int:
    try:
        banned = bootstrap.parse_banlist(read_banfile(args.banlist))
    except OSError as exc:
        return fail("cannot read %s: %s (run it with sudo)" % (args.banlist, exc.strerror))
    if not banned:
        print("No suspended numbers (%s)." % args.banlist)
        return 0
    print("%d suspended number(s) in %s:" % (len(banned), args.banlist))
    for phone, note in banned.items():
        print("  %s  %s" % (phone, safe(note)) if note else "  %s" % phone)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hoppin_admin.py",
        description="Review abuse reports and suspend numbers on the hoppin relay.")
    parser.add_argument("--reports", help="reports file (default: HOPPIN_REPORTS)")
    parser.add_argument("--banlist", help="ban file (default: HOPPIN_BANLIST)")
    # The same flags after the command too; SUPPRESS keeps a value given
    # before it.
    paths = argparse.ArgumentParser(add_help=False)
    paths.add_argument("--reports", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    paths.add_argument("--banlist", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True

    p = sub.add_parser("reports", parents=[paths], help="list reports, newest first")
    p.add_argument("--since", dest="since_text", metavar="AGE",
                   help="only reports newer than this, e.g. 24h, 7d")
    p.add_argument("--evidence", action="store_true",
                   help="also print the messages the reporter attached")
    p.set_defaults(func=cmd_reports)

    p = sub.add_parser("ban", parents=[paths], help="suspend a number")
    p.add_argument("phone", type=phone_arg, help="E.164, e.g. +351912345678")
    p.add_argument("note", nargs="*", help="optional note, kept in the ban file")
    p.set_defaults(func=cmd_ban)

    p = sub.add_parser("unban", parents=[paths], help="lift a suspension")
    p.add_argument("phone", type=phone_arg, help="E.164, e.g. +351912345678")
    p.set_defaults(func=cmd_unban)

    p = sub.add_parser("banned", parents=[paths], help="list suspended numbers")
    p.set_defaults(func=cmd_banned)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.reports = resolve_path(args.reports, "HOPPIN_REPORTS", bootstrap.REPORTS_PATH)
    args.banlist = resolve_path(args.banlist, "HOPPIN_BANLIST", bootstrap.BANLIST_PATH)
    if getattr(args, "since_text", None):
        try:
            args.since = parse_duration(args.since_text)
        except argparse.ArgumentTypeError as exc:
            parser.error(str(exc))
    else:
        args.since = None
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
