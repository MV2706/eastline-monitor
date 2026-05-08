#!/usr/bin/env python3
"""
Eastline Residences 2BR availability checker.

Fetches the floorplans page (using curl_cffi to bypass Cloudflare's JS
challenge), parses every floorplan's name + status, filters to 2BR units,
compares against a state file, and emails the user via Gmail SMTP whenever
something changes.

Usage:
    python3 eastline_checker.py <state_path> [html_path]

If <html_path> is provided, the script reads HTML from that file instead of
fetching live (useful for testing).

Required env vars (loaded from secrets.env in the script's directory):
    EASTLINE_GMAIL_FROM           your Gmail address (sender)
    EASTLINE_GMAIL_APP_PASSWORD   16-char app password from
                                  myaccount.google.com/apppasswords
    EASTLINE_EMAIL_TO             alert recipient (defaults to FROM)

Returns:
    0 = ran successfully (whether or not changes were found)
    2 = parse error (page may have been a CF challenge instead of real content)
    3 = network error
"""

import json
import os
import re
import smtplib
import ssl
import sys
import urllib.request
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

EASTLINE_URL = "https://www.eastlineresidences.com/floorplans?Beds=2"


def fetch_page() -> str:
    """Fetch the floorplans page, bypassing Cloudflare via TLS fingerprint impersonation."""
    try:
        from curl_cffi import requests as cf_requests  # type: ignore
    except ImportError:
        print("ERROR: curl_cffi not installed. Run: pip install curl_cffi", file=sys.stderr)
        sys.exit(3)

    try:
        r = cf_requests.get(EASTLINE_URL, impersonate="chrome", timeout=30)
    except Exception as e:
        print(f"ERROR: fetch failed: {e}", file=sys.stderr)
        sys.exit(3)

    if r.status_code != 200:
        print(f"ERROR: HTTP {r.status_code} from Eastline", file=sys.stderr)
        sys.exit(3)

    return r.text


# Each floorplan has a hidden modal in the HTML containing the canonical
# unit-level data — including a per-floorplan "Available On: M/D/YYYY" date
# when the leasing system has scheduled an upcoming vacancy. The card on the
# main page only shows a summary ("X Available" or "Inquire for details").
#
# The richer "Available On" data is what we want to monitor: it tells us when
# a 2BR unit will become available, even before its leasing flag flips from
# "Inquire" to "Apply". This is critical for catching units the moment their
# move-in date is set — typically the moment the existing tenant gives notice.
MODAL_RE = re.compile(
    r'<div id="modal-content-(\d+)"[^>]*class="modal-content"[^>]*>(.*?)</section>',
    re.DOTALL,
)

# fp-availability span on the card shows a count for floorplans that have
# units bookable RIGHT NOW (the apply path).
COUNT_RE = re.compile(
    r'data-floorplan-id="(\d+)"[^>]*data-original="(\d+)"[^>]*'
    r'class="fp-availability"[^>]*>(\d+)\s+Available',
)


def _parse_modal(fp_id: str, body: str) -> dict | None:
    name_m = re.search(r'<h2[^>]*>([^<]+)</h2>', body)
    if not name_m:
        return None
    name = name_m.group(1).strip()

    beds_m = re.search(r'(\d+)\s+Beds?', body)
    baths_m = re.search(r'(\d+(?:\.\d+)?)\s+Baths?', body)
    sqft_m = re.search(r'([\d,]+)\s+Sq\.\s*Ft', body)
    price_m = re.search(
        r"\$([\d,]+(?:\.\d+)?)<span class='sr-only'>to</span>-\$([\d,]+(?:\.\d+)?)",
        body,
    )
    # "Available On" inside the modal can be either:
    #   - "M/D/YYYY" - a specific future date the unit becomes ready
    #   - "Available Now" - one or more units are vacant today
    #   - missing - no upcoming vacancy known
    avail_m = re.search(
        r'Available On:\s*</span>\s*<span>([^<]+)</span>', body
    )

    has_apply = bool(re.search(r'class="[^"]*track-apply[^"]*"', body))
    has_dialog = bool(
        re.search(r'class="[^"]*(?:track-dialog|dialog-button)[^"]*"', body)
    )

    def _i(m, default=0):
        if not m:
            return default
        return int(m.group(1).replace(",", "").split(".")[0])

    return {
        "fp_id": fp_id,
        "name": name,
        "beds": _i(beds_m),
        "baths": float(baths_m.group(1)) if baths_m else 0.0,
        "sqft": _i(sqft_m),
        "price_low": _i(price_m, default=0),
        "price_high": (
            int(price_m.group(2).replace(",", "").split(".")[0])
            if price_m
            else 0
        ),
        "available_on": avail_m.group(1).strip() if avail_m else None,
        "status": "available" if has_apply else "inquire" if has_dialog else "unknown",
        "count": 0,  # filled below for apply-path floorplans
    }


def parse_floorplans(html: str) -> list[dict]:
    """Return one dict per UNIQUE floorplan with its full status snapshot."""
    plans: dict[str, dict] = {}

    for fp_id, modal_body in MODAL_RE.findall(html):
        rec = _parse_modal(fp_id, modal_body)
        if rec is None:
            continue
        plans.setdefault(rec["name"], rec)

    # Overlay the "N Available" count from the card-level fp-availability span.
    # The span links to floorplan-id, so we can match exactly.
    count_by_id = {
        fp_id: int(count) for fp_id, _, count in COUNT_RE.findall(html)
    }
    for rec in plans.values():
        rec["count"] = count_by_id.get(rec["fp_id"], 0)

    return list(plans.values())


def detect_cloudflare_challenge(html: str) -> bool:
    return "Just a moment..." in html and "challenge-platform" in html


def filter_2br(floorplans: list[dict]) -> list[dict]:
    return [fp for fp in floorplans if fp["beds"] == 2]


def snapshot_signature(floorplans: list[dict]) -> dict:
    """A normalized signature dict used for diffing across runs."""
    return {
        fp["name"]: {
            "status": fp["status"],
            "count": fp["count"],
            "available_on": fp["available_on"],
            "price_low": fp["price_low"],
            "price_high": fp["price_high"],
        }
        for fp in sorted(floorplans, key=lambda x: x["name"])
    }


def diff_snapshots(prev: dict, curr: dict) -> list[str]:
    """Return human-readable change lines, ordered by importance.

    The most important events (new available-on date, status flip to apply)
    are surfaced first.
    """
    changes = []
    all_names = set(prev) | set(curr)
    for name in sorted(all_names):
        p = prev.get(name)
        c = curr.get(name)
        if p is None:
            extra = (
                f" [available {c['available_on']}]"
                if c.get("available_on")
                else ""
            )
            changes.append(
                f"NEW PLAN: {name} -> {c['status']} "
                f"({c['count']} avail) ${c['price_low']}-{c['price_high']}{extra}"
            )
            continue
        if c is None:
            changes.append(f"GONE: {name} (was {p['status']})")
            continue

        # Available-on transitions are the gold signal — surface them first.
        p_av = p.get("available_on")
        c_av = c.get("available_on")
        if p_av != c_av:
            if c_av and not p_av:
                changes.append(
                    f"NEW AVAILABLE DATE: {name} now slated to open "
                    f"{c_av} (status: {c['status']}, "
                    f"${c['price_low']}-{c['price_high']})"
                )
            elif p_av and not c_av:
                changes.append(
                    f"AVAILABLE DATE GONE: {name} no longer shows "
                    f"open date (was {p_av})"
                )
            else:
                changes.append(
                    f"AVAILABLE DATE CHANGED: {name} {p_av} -> {c_av}"
                )

        if p["status"] != c["status"]:
            changes.append(
                f"STATUS CHANGE: {name} {p['status']} -> {c['status']} "
                f"(count {p['count']} -> {c['count']}, "
                f"available {c.get('available_on') or 'TBD'})"
            )
        elif p["count"] != c["count"]:
            changes.append(
                f"COUNT CHANGE: {name} {p['count']} -> {c['count']} available "
                f"(available {c.get('available_on') or 'TBD'})"
            )
        elif (
            p["price_low"] != c["price_low"]
            or p["price_high"] != c["price_high"]
        ):
            changes.append(
                f"PRICE CHANGE: {name} ${p['price_low']}-{p['price_high']} -> "
                f"${c['price_low']}-{c['price_high']}"
            )
    return changes


def send_email_smtp(
    sender: str,
    app_password: str,
    recipient: str,
    subject: str,
    body: str,
) -> None:
    """Send an email through Gmail's SMTP server using an app password.

    sender / recipient can be the same (you emailing yourself).
    app_password is the 16-character string from myaccount.google.com/apppasswords.
    """
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body)

    ctx = ssl.create_default_context()
    with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as smtp:
        smtp.starttls(context=ctx)
        # App passwords are shown with spaces for readability; SMTP doesn't care
        # but strip them just in case.
        smtp.login(sender, app_password.replace(" ", ""))
        smtp.send_message(msg)


def push_ntfy(
    topic: str,
    title: str,
    message: str,
    priority: str = "default",
    tags: str = "house",
    email_to: str | None = None,
) -> None:
    """POST to ntfy.sh.

    If ``email_to`` is provided, ntfy.sh forwards the message via email to
    that address instead of (or in addition to) any push subscribers on the
    topic.

    Topic = whatever secret string the user picked. If only email is desired
    and no app subscribers exist, the topic is just a routing handle — keep
    it unguessable so random POSTs don't trigger emails.
    """
    url = f"https://ntfy.sh/{topic}"
    headers = {
        "Title": title,
        "Priority": priority,
        "Tags": tags,
        "Click": "https://www.eastlineresidences.com/floorplans?Beds=2",
    }
    if email_to:
        headers["Email"] = email_to

    req = urllib.request.Request(
        url,
        data=message.encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        resp.read()


def load_env_file(path: str) -> None:
    """Read a KEY=value file and merge into os.environ (no overwrite)."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip('"').strip("'")
        os.environ.setdefault(k, v)


def main() -> int:
    if len(sys.argv) < 2:
        print(
            "usage: eastline_checker.py <state_path> [html_path]\n"
            "\n"
            "Required env vars (typically loaded from secrets.env in the same\n"
            "directory as this script):\n"
            "  EASTLINE_GMAIL_FROM           sender Gmail address\n"
            "  EASTLINE_GMAIL_APP_PASSWORD   16-char Gmail app password\n"
            "  EASTLINE_EMAIL_TO             alert recipient (defaults to FROM)\n",
            file=sys.stderr,
        )
        return 64

    # Load secrets.env from the script's directory if present.
    script_dir = Path(__file__).resolve().parent
    load_env_file(str(script_dir / "secrets.env"))

    state_path = sys.argv[1]
    html_path = sys.argv[2] if len(sys.argv) > 2 else None

    email_from = os.environ.get("EASTLINE_GMAIL_FROM")
    email_pw = os.environ.get("EASTLINE_GMAIL_APP_PASSWORD")
    email_to = os.environ.get("EASTLINE_EMAIL_TO") or email_from

    if html_path:
        html = Path(html_path).read_text(encoding="utf-8", errors="replace")
    else:
        html = fetch_page()

    if detect_cloudflare_challenge(html):
        print("ERROR: page is a Cloudflare challenge, not real content.", file=sys.stderr)
        return 2

    floorplans = parse_floorplans(html)
    if not floorplans:
        print("ERROR: parsed 0 floorplans. HTML structure may have changed.", file=sys.stderr)
        return 2

    two_br = filter_2br(floorplans)
    snapshot = snapshot_signature(two_br)
    available_2br = [fp for fp in two_br if fp["status"] == "available"]

    state_file = Path(state_path)
    prev_snapshot = {}
    first_run = not state_file.exists()
    if not first_run:
        try:
            prev_snapshot = json.loads(state_file.read_text())
        except Exception:
            prev_snapshot = {}

    changes = diff_snapshots(prev_snapshot, snapshot)

    now_iso = datetime.now().isoformat(timespec="seconds")
    two_br_with_date = [fp for fp in two_br if fp.get("available_on")]
    summary = (
        f"[{now_iso}] 2BR floorplans: {len(two_br)} total, "
        f"{len(available_2br)} bookable now, "
        f"{len(two_br_with_date)} with future available date"
    )
    print(summary)
    for fp in sorted(two_br, key=lambda x: x["sqft"]):
        marker = "  AVAILABLE" if fp["status"] == "available" else "  inquire  "
        cnt = f"x{fp['count']}" if fp["count"] else "   "
        avail = (
            f"  open {fp['available_on']}"
            if fp.get("available_on")
            else ""
        )
        price = (
            f"${fp['price_low']}-{fp['price_high']}"
            if fp["price_low"]
            else "$?-?"
        )
        print(f"  {marker} {cnt}  {fp['name']:30s} {price:18s}{avail}")

    if changes:
        print("\nCHANGES SINCE LAST RUN:")
        for line in changes:
            print(f"  - {line}")

    # Decide whether to send an email.
    # On first run, send a baseline confirmation so user knows it's armed.
    # On subsequent runs, send only when something actually changed.
    def _fmt_fp(fp):
        bits = [f"  - {fp['name']}: {fp['status']}"]
        if fp["count"]:
            bits.append(f"({fp['count']} bookable now)")
        if fp.get("available_on"):
            bits.append(f"available {fp['available_on']}")
        if fp["price_low"]:
            bits.append(f"${fp['price_low']}-{fp['price_high']}/mo")
        return " ".join(bits)

    notification = None
    if first_run:
        subject = (
            f"[Eastline] checker armed - "
            f"{len(available_2br)} bookable, "
            f"{len(two_br_with_date)} dated 2BRs"
        )
        body = (
            "Hourly monitor is live. You'll get an email whenever any 2BR\n"
            "inventory changes at Eastline Residences. Especially:\n"
            "  * a new 2BR appears with an Available On date set\n"
            "  * an existing dated 2BR flips from Inquire to Apply\n"
            "  * an Available On date moves earlier (sometimes happens\n"
            "    when a tenant gives shorter notice)\n\n"
            "Current 2BR snapshot:\n"
        )
        body += "\n".join(_fmt_fp(fp) for fp in sorted(two_br, key=lambda x: x["sqft"]))
        if two_br_with_date:
            body += "\n\n2BRs with a known future available date right now:\n"
            body += "\n".join(
                _fmt_fp(fp)
                for fp in sorted(two_br_with_date, key=lambda x: x["available_on"])
            )
        body += "\n\nLink: https://www.eastlineresidences.com/floorplans?Beds=2\n"
        notification = (subject, body)
    elif changes:
        # Categorize change importance
        flipped_to_apply = [
            line for line in changes
            if "STATUS CHANGE" in line and "-> available" in line
        ]
        new_dates = [line for line in changes if "NEW AVAILABLE DATE" in line]
        new_plans = [line for line in changes if "NEW PLAN" in line and "[available" in line]
        priority_events = flipped_to_apply + new_dates + new_plans

        if flipped_to_apply:
            subject = (
                f"!! [Eastline] 2BR JUST OPENED FOR APPLICATION "
                f"({len(flipped_to_apply)})"
            )
        elif new_dates or new_plans:
            subject = (
                f"!! [Eastline] new 2BR available date set "
                f"({len(new_dates) + len(new_plans)})"
            )
        else:
            subject = f"[Eastline] 2BR inventory changed ({len(changes)})"

        body = "Changes since the last hourly check:\n\n"
        if priority_events:
            body += "PRIORITY:\n" + "\n".join(f"  - {l}" for l in priority_events) + "\n\n"
        other_events = [c for c in changes if c not in priority_events]
        if other_events:
            body += "Other changes:\n" + "\n".join(f"  - {l}" for l in other_events) + "\n\n"
        body += "Full current 2BR snapshot:\n"
        body += "\n".join(
            _fmt_fp(fp) for fp in sorted(two_br, key=lambda x: x["sqft"])
        )
        body += "\n\nLink: https://www.eastlineresidences.com/floorplans?Beds=2\n"
        notification = (subject, body)

    if notification:
        subject, body = notification
        if email_from and email_pw and email_to:
            try:
                send_email_smtp(email_from, email_pw, email_to, subject, body)
                print(f"[email] sent to {email_to!r}: {subject!r}")
            except Exception as e:
                print(f"[email] FAILED to send: {e}", file=sys.stderr)
        else:
            print(
                "[email] SKIPPED — set EASTLINE_GMAIL_FROM, EASTLINE_GMAIL_APP_PASSWORD,"
                " EASTLINE_EMAIL_TO in secrets.env to enable.",
                file=sys.stderr,
            )
            print(f"  would have sent: {subject}")
    else:
        print("(no changes; no email sent)")

    # Persist new state.
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(snapshot, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
