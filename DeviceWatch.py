#!/usr/bin/env python3
"""
DeviceWatch v2 - automated health, security and maintenance monitor for your PC / laptop.

Monitors : CPU, RAM, swap, disks (+SMART health, I/O speed), GPU, temperature/fans/throttling,
           battery status/health, network quality + speed tests + Wi-Fi signal + bandwidth,
           uptime, boot time, memory-leak suspects, backups, failed logins, system errors.
Security : antivirus/firewall status, suspicious processes, new startup items, hosts-file
           tampering, open ports, suspicious outbound connections, file-integrity monitoring,
           ransomware canary files, USB device alerts, optional hash blocklist + VirusTotal.
Updates  : pending OS and application updates.
Alerts   : desktop, email, Telegram, webhook (Slack/Discord/WhatsApp gateways), quiet hours,
           critical-alert escalation, daily/weekly summary.
Fixes    : safe auto-fixes (temp files, browser caches, recycle bin, DNS flush), auto-restart
           of chosen services.
Dashboard: live local dashboard with history ranges, spike finder, dark/light theme, mobile
           layout, optional password, HTML/PDF report, multi-device hub.

Setup   : pip install psutil            (optional: pip install pystray pillow   for tray icon)
Run     : python devicewatch.py                  monitor + dashboard (opens your browser)
          python devicewatch.py --no-browser     same, browser stays closed
          python devicewatch.py --once           one-off report in the terminal, then exit
          python devicewatch.py --report         one-off check, save an HTML report, then exit
          python devicewatch.py --tray           run with a system-tray icon
          python devicewatch.py --install-startup    start automatically at login
          python devicewatch.py --uninstall-startup  remove the auto-start entry
          python devicewatch.py --init           write an editable config file
Package : pip install pyinstaller pystray pillow
          pyinstaller --onefile --noconsole devicewatch.py      (exe appears in ./dist)
"""
import argparse
import base64
import hashlib
import html
import ipaddress
import json
import logging
import os
import platform
import plistlib
import re
import secrets
import shlex
import shutil
import smtplib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import xml.etree.ElementTree as ET
from collections import Counter, deque
from datetime import datetime, timedelta
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:
    import psutil
except ImportError:
    sys.exit("Missing dependency. Install it with:  pip install psutil")

HOME = Path.home() / ".devicewatch"
CONFIG_PATH = HOME / "config.json"
LOG_PATH = HOME / "devicewatch.log"
HISTORY_PATH = HOME / "history.jsonl"
SPEED_PATH = HOME / "speedtests.jsonl"
STATE_PATH = HOME / "security_state.json"
BLOCKLIST_PATH = HOME / "blocklist.txt"      # optional: one SHA-256 per line
BAD_IPS_PATH = HOME / "bad_ips.txt"          # optional: one known-bad IP per line
REPORT_DIR = HOME / "reports"
OS = platform.system()  # Windows / Darwin / Linux

DEFAULT_CONFIG = {
    "device_name": "",                 # shown in the multi-device hub (default: computer name)
    "interval_seconds": 30,
    "history_days": 30,
    # --- thresholds
    "cpu_percent": 90,
    "cpu_sustained_samples": 4,        # consecutive samples above threshold
    "ram_percent": 90,
    "swap_percent": 80,
    "disk_percent": 90,
    "disk_free_gb_min": 5,
    "disk_busy_warn_percent": 95,      # sustained disk busy time (Linux only)
    "cpu_temp_c": 85,
    "gpu_temp_c": 85,
    "battery_low_percent": 15,
    "battery_health_warn_percent": 70,
    "uptime_days_warn": 14,
    "boot_slow_seconds": 120,
    "wifi_signal_warn_percent": 30,
    # --- network
    "network_check_host": "8.8.8.8",
    "network_check_port": 443,
    "network_probe_count": 3,
    "network_latency_warn_ms": 250,
    "speedtest_enabled": True,         # downloads a few MB from Cloudflare every few hours
    "speedtest_hours": 6,
    "speedtest_download_mb": 5,
    "speedtest_warn_mbps": 5,
    "scan_open_ports": True,
    "watch_outbound": True,
    "connection_scan_seconds": 120,
    "suspicious_remote_ports": [3333, 4444, 5555, 7777, 14444, 14433, 45560],
    # --- backups / hardware
    "backup_paths": [],                # backup files or directories to check
    "backup_max_age_days": 7,
    "backup_check_hours": 1,
    "check_disk_health": True,
    "disk_health_check_hours": 6,
    "leak_check_enabled": True,        # flag processes whose memory keeps growing
    "leak_window_minutes": 60,
    "leak_growth_mb": 300,
    "boot_analysis_enabled": True,
    "scan_system_errors": True,
    "system_errors_per_hour_warn": 20,
    "failed_logins_per_hour_warn": 5,  # needs admin on Windows
    # --- security
    "scan_malware": True,
    "scan_interval_minutes": 10,       # how often the security scan runs
    "signature_max_age_days": 3,       # warn if antivirus definitions are older
    "ignore_process_names": [],        # e.g. ["myportableapp.exe"] to silence false positives
    "virustotal_api_key": "",          # optional: only file HASHES are sent
    "integrity_paths": [],             # folders/files to watch for unexpected changes
    "integrity_max_files": 2000,
    "integrity_check_minutes": 30,
    "canary_enabled": True,            # plants small decoy files in Documents/Desktop
    "usb_alerts": True,
    # --- updates
    "check_updates": True,
    "update_check_hours": 6,
    "check_app_updates": True,
    "app_check_hours": 12,
    # --- alerts
    "alert_cooldown_minutes": 30,
    "desktop_notifications": True,
    "quiet_hours_enabled": False,      # suppresses non-critical desktop popups
    "quiet_hours_start": "22:00",
    "quiet_hours_end": "07:00",
    "escalate_critical": True,         # repeat critical alerts until fixed
    "escalation_minutes": 10,
    "summary_enabled": False,          # daily/weekly summary
    "summary_frequency": "daily",      # daily | weekly (Mondays)
    "summary_hour": 8,
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "webhook_url": "",                 # POSTs {"text": "...", "content": "..."}
    "email": {
        "enabled": False,
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "username": "",
        "password": "",                # use an app password, not your real one
        "to": "",
    },
    # --- automatic fixes
    "auto_fix": False,                 # master switch for fixes triggered by alerts
    "auto_fix_actions": ["temp", "browser_cache"],   # temp | browser_cache | recycle_bin | dns
    "watch_services": [],              # service names to restart if they stop (Windows/Linux)
    "service_restart_max_per_hour": 3,
    # --- dashboard / multi-device
    "dashboard_host": "127.0.0.1",     # use 0.0.0.0 only together with dashboard_password
    "dashboard_port": 8765,
    "dashboard_password": "",
    "hub_enabled": False,              # this computer collects status from other computers
    "hub_token": "",                   # shared secret between hub and agents
    "hub_url": "",                     # agents: e.g. http://192.168.1.10:8765
}

SECRET_KEYS = ("virustotal_api_key", "telegram_bot_token", "dashboard_password", "hub_token", "webhook_url")
MASK = "********"
RANGES = {"1h": 1, "24h": 24, "7d": 168, "30d": 720}
STATE_LOCK = threading.Lock()


def load_config():
    HOME.mkdir(exist_ok=True)
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if CONFIG_PATH.exists():
        try:
            user = json.loads(CONFIG_PATH.read_text())
            for k, v in user.items():
                if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                    cfg[k].update(v)
                else:
                    cfg[k] = v
        except Exception as e:
            print(f"Could not read config ({e}); using defaults.")
    return cfg


def save_config(cfg):
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(CONFIG_PATH, 0o600)     # config can hold passwords/tokens
    except OSError:
        pass


def public_config(cfg):
    out = json.loads(json.dumps(cfg))
    for k in SECRET_KEYS:
        if out.get(k):
            out[k] = MASK
    if out.get("email", {}).get("password"):
        out["email"]["password"] = MASK
    return out


def coerce(old, new):
    if isinstance(old, bool):
        return bool(new)
    if isinstance(old, (int, float)) and isinstance(new, (int, float)) and not isinstance(new, bool):
        return new
    if isinstance(old, list) and isinstance(new, list):
        return new
    if isinstance(old, str) and isinstance(new, str):
        return new
    return old


def apply_config(cfg, data):
    for k, v in data.items():
        if k not in cfg:
            continue
        if isinstance(cfg[k], dict) and isinstance(v, dict):
            for k2, v2 in v.items():
                if k2 in cfg[k] and v2 != MASK:
                    cfg[k][k2] = coerce(cfg[k][k2], v2)
        elif v != MASK:
            cfg[k] = coerce(cfg[k], v)


def gb(n):
    return round(n / 1024 ** 3, 1)


def load_state():
    try:
        return json.loads(STATE_PATH.read_text())
    except Exception:
        return {}


def save_state(st):
    try:
        STATE_PATH.write_text(json.dumps(st))
    except OSError:
        pass


def in_quiet_hours(cfg):
    if not cfg.get("quiet_hours_enabled"):
        return False
    try:
        start = datetime.strptime(cfg["quiet_hours_start"], "%H:%M").time()
        end = datetime.strptime(cfg["quiet_hours_end"], "%H:%M").time()
    except (ValueError, KeyError):
        return False
    now = datetime.now().time()
    return (start <= now < end) if start <= end else (now >= start or now < end)


# ------------------------------------------------------------ system helpers
CREATE_NO_WINDOW = 0x08000000 if OS == "Windows" else 0
MINER_NAMES = ("xmrig", "minerd", "cpuminer", "nbminer", "phoenixminer", "lolminer",
               "ethminer", "cgminer", "bfgminer", "mimikatz", "lazagne")
WIN_SYSTEM_PROCS = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
                    "services.exe", "smss.exe", "wininit.exe"}
RISKY_DIRS = {
    "Windows": ("\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\", "\\$recycle.bin\\"),
    "Linux": ("/tmp/", "/dev/shm/", "/var/tmp/"),
    "Darwin": ("/tmp/", "/private/tmp/", "/private/var/tmp/", "/users/shared/", "/downloads/"),
}
MALWARE_FIX = ("Don't open it. End the process, then run a full antivirus scan "
               "(Windows: Windows Security > Virus & threat protection > Scan options > Microsoft Defender Offline scan; "
               "Linux: clamscan -r ~). If it returns or you don't recognise it, disconnect from the network and change your passwords from a clean device.")
WIN_UPDATE_PS = (
    "$s=New-Object -ComObject Microsoft.Update.Session;"
    "$r=$s.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0');"
    "$r.Updates | ForEach-Object { [pscustomobject]@{Title=$_.Title;"
    "Sec=(@($_.Categories | Where-Object { $_.Name -match 'Security|Critical' }).Count -gt 0)} } "
    "| ConvertTo-Json -Compress"
)
CANARY_NAME = "!_devicewatch_canary_do_not_edit.txt"
CANARY_TEXT = ("DeviceWatch canary file. If this file is changed, renamed or deleted, ransomware or a rogue\n"
               "program may be tampering with your documents. Leave it alone.\n")
SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@:\- ]{1,100}$")


def run(cmd, timeout=60):
    try:
        kw = {"creationflags": CREATE_NO_WINDOW} if CREATE_NO_WINDOW else {}
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                              timeout=timeout, **kw).stdout or ""
    except Exception:
        return ""


def ps(script, timeout=90):
    return run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout)


def shutil_which(cmd):
    return shutil.which(cmd)


def protection_status():
    """Is real-time protection / firewall on? Returns av_ok/firewall_ok as True/False/None(unknown)."""
    s = {"av_ok": None, "av_names": [], "sig_age": None, "firewall_ok": None, "notes": []}
    try:
        if OS == "Windows":
            out = ps("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
                     "Select-Object displayName,productState | ConvertTo-Json -Compress")
            if out.strip():
                d = json.loads(out)
                d = d if isinstance(d, list) else [d]
                on = [p["displayName"] for p in d if format(int(p["productState"]), "06x")[2:4] in ("10", "11")]
                s["av_names"], s["av_ok"] = on, bool(on)
                if any("defender" in n.lower() for n in on):
                    o2 = ps("Get-MpComputerStatus | Select-Object AntivirusSignatureAge | ConvertTo-Json -Compress")
                    if o2.strip():
                        s["sig_age"] = json.loads(o2).get("AntivirusSignatureAge")
            fw = ps("Get-NetFirewallProfile | ForEach-Object { $_.Name + '=' + $_.Enabled }")
            if fw.strip():
                s["firewall_ok"] = "=False" not in fw
        elif OS == "Darwin":
            gk = run(["spctl", "--status"]).lower()
            sip = run(["csrutil", "status"]).lower()
            fw = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]).lower()
            if gk:
                s["av_names"], s["av_ok"] = ["Gatekeeper/XProtect"], "assessments enabled" in gk
            if sip and "enabled" not in sip:
                s["notes"].append("System Integrity Protection (SIP) is disabled.")
            if fw:
                s["firewall_ok"] = "enabled" in fw
        else:
            s["av_names"] = [v for v in ("clamav-daemon", "clamd@scan")
                             if run(["systemctl", "is-active", v]).strip() == "active"]
            s["av_ok"] = True if s["av_names"] else None   # antivirus is optional on Linux
            states = [run(["systemctl", "is-active", v]).strip() for v in ("ufw", "firewalld", "nftables")]
            if "active" in states:
                s["firewall_ok"] = True
            elif "inactive" in states:
                s["firewall_ok"] = False
    except Exception as e:
        logging.warning("Protection status check failed: %s", e)
    return s


def autostart_entries():
    """Things that run automatically at login/boot (a favourite hiding place for malware)."""
    items = set()
    try:
        if OS == "Windows":
            import winreg
            for hive, hn in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
                for sub in (r"Software\Microsoft\Windows\CurrentVersion\Run",
                            r"Software\Microsoft\Windows\CurrentVersion\RunOnce"):
                    leaf = sub.rsplit("\\", 1)[-1]
                    try:
                        with winreg.OpenKey(hive, sub) as k:
                            i = 0
                            while True:
                                try:
                                    name, val, _ = winreg.EnumValue(k, i)
                                except OSError:
                                    break
                                items.add(f"reg:{hn}\\{leaf}:{name}={val}")
                                i += 1
                    except OSError:
                        pass
            for base in (os.environ.get("APPDATA"), os.environ.get("PROGRAMDATA")):
                if base:
                    d = Path(base) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
                    if d.is_dir():
                        items.update(f"startup:{f.name}" for f in d.iterdir())
            for line in run(["schtasks", "/query", "/fo", "csv", "/nh"]).splitlines():
                name = line.split('","')[0].strip('"')
                if name and not name.startswith("\\Microsoft\\"):
                    items.add("task:" + name)
        elif OS == "Darwin":
            for d in (Path.home() / "Library/LaunchAgents", Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")):
                if d.is_dir():
                    items.update(f"{d}/{f.name}" for f in d.iterdir())
        else:
            home = Path.home()
            for d in (home / ".config/autostart", home / ".config/systemd/user"):
                if d.is_dir():
                    items.update(f"{d}/{f.name}" for f in d.iterdir())
            items.update("cron:" + l.strip() for l in run(["crontab", "-l"]).splitlines()
                         if l.strip() and not l.startswith("#"))
    except Exception as e:
        logging.warning("Autostart scan failed: %s", e)
    return items


def check_updates():
    """Pending OS updates / patches. Returns titles, how many are security-related, reboot flag."""
    info = {"titles": [], "security": 0, "reboot": False,
            "checked": datetime.now().isoformat(timespec="seconds")}
    try:
        if OS == "Windows":
            out = ps(WIN_UPDATE_PS, timeout=240).strip()
            if out:
                d = json.loads(out)
                d = d if isinstance(d, list) else [d]
                info["titles"] = [x["Title"] for x in d]
                info["security"] = sum(1 for x in d if x.get("Sec"))
            import winreg
            for sub in (r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"):
                try:
                    winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub))
                    info["reboot"] = True
                except OSError:
                    pass
        elif OS == "Darwin":
            out = run(["softwareupdate", "-l"], 180)
            for line in out.splitlines():
                t = line.strip()
                if t.startswith("* Label:"):
                    info["titles"].append(t[8:].strip())
                elif t.startswith("* "):
                    info["titles"].append(t[2:].strip())
            info["security"] = sum(1 for t in info["titles"] if "security" in t.lower() or "xprotect" in t.lower())
            info["reboot"] = "restart" in out.lower()
        else:
            if shutil_which("apt"):
                for line in run(["apt", "list", "--upgradable"], 90).splitlines():
                    if "upgradable" in line and "/" in line:
                        info["titles"].append(line.split("/")[0])
                        if "-security" in line:
                            info["security"] += 1
            elif shutil_which("dnf"):
                info["titles"] = [l.split()[0] for l in run(["dnf", "-q", "check-update"], 180).splitlines()
                                  if len(l.split()) == 3 and "." in l.split()[0]]
                info["security"] = len([l for l in run(["dnf", "-q", "check-update", "--security"], 180).splitlines()
                                        if len(l.split()) == 3 and "." in l.split()[0]])
            elif shutil_which("checkupdates"):
                info["titles"] = [l.split()[0] for l in run(["checkupdates"], 120).splitlines() if l.strip()]
            info["reboot"] = Path("/var/run/reboot-required").exists()
    except Exception as e:
        info["error"] = str(e)
    info["count"] = len(info["titles"])
    return info


def battery_health():
    """Return battery health metrics when the OS exposes design/full capacity."""
    designed = full = cycles = None
    try:
        if OS == "Windows":
            script = (
                "$d=Get-CimInstance -Namespace root/WMI -ClassName BatteryStaticData;"
                "$f=Get-CimInstance -Namespace root/WMI -ClassName BatteryFullChargedCapacity;"
                "if($d -and $f){[pscustomobject]@{DesignedCapacity=($d | Measure-Object DesignedCapacity -Sum).Sum;"
                "FullChargedCapacity=($f | Measure-Object FullChargedCapacity -Sum).Sum} | ConvertTo-Json -Compress}"
            )
            out = ps(script).strip()
            if out:
                data = json.loads(out)
                designed, full = data.get("DesignedCapacity"), data.get("FullChargedCapacity")
            if not designed or not full:
                with tempfile.TemporaryDirectory(prefix="devicewatch-") as temp_dir:
                    report = Path(temp_dir) / "battery-report.xml"
                    run(["powercfg", "/batteryreport", "/xml", "/output", str(report)], 30)
                    if report.is_file():
                        root = ET.parse(report).getroot()
                        batteries = [node for node in root.iter()
                                     if node.tag.rsplit("}", 1)[-1] == "Battery"]
                        readings = []
                        for battery in batteries:
                            values = {child.tag.rsplit("}", 1)[-1]: child.text for child in battery}
                            try:
                                reading = (int(values["FullChargeCapacity"]),
                                           int(values["DesignCapacity"]))
                            except (KeyError, TypeError, ValueError):
                                continue
                            if reading[1] > 0:
                                readings.append(reading)
                            if cycles is None and values.get("CycleCount"):
                                try:
                                    cycles = int(values["CycleCount"])
                                except ValueError:
                                    pass
                        if readings:
                            full, designed = sum(item[0] for item in readings), sum(item[1] for item in readings)
        elif OS == "Linux":
            batteries = [p for p in Path("/sys/class/power_supply").glob("BAT*") if p.is_dir()]
            pairs = []
            for battery in batteries:
                for full_name, design_name in (("energy_full", "energy_full_design"),
                                               ("charge_full", "charge_full_design")):
                    try:
                        pair = (int((battery / full_name).read_text().strip()),
                                int((battery / design_name).read_text().strip()))
                    except (OSError, ValueError):
                        continue
                    if pair[1] > 0:
                        pairs.append(pair)
                        break
            if pairs:
                full, designed = sum(p[0] for p in pairs), sum(p[1] for p in pairs)
            for battery in batteries:
                try:
                    cycles = int((battery / "cycle_count").read_text().strip())
                    break
                except (OSError, ValueError):
                    continue
        elif OS == "Darwin":
            out = run(["system_profiler", "SPPowerDataType"], 30)
            condition = re.search(r"Condition:\s*(.+)", out, re.IGNORECASE)
            capacity = re.search(r"Maximum Capacity:\s*(\d+)\s*%", out, re.IGNORECASE)
            cycle_count = re.search(r"Cycle Count:\s*(\d+)", out, re.IGNORECASE)
            if capacity:
                health = int(capacity.group(1))
                result = {"battery_health_percent": health,
                          "battery_wear_percent": max(0, 100 - health)}
                if condition:
                    result["battery_health_label"] = condition.group(1).strip()
                if cycle_count:
                    result["battery_cycle_count"] = int(cycle_count.group(1))
                return result
    except (OSError, ValueError, TypeError, json.JSONDecodeError, ET.ParseError):
        return {}

    if not designed or not full or designed <= 0:
        return {}
    health = max(0, min(100, round(full * 100 / designed)))
    result = {"battery_health_percent": health,
              "battery_wear_percent": max(0, 100 - health),
              "battery_health_label": "Good" if health >= 80 else "Fair" if health >= 60 else "Poor"}
    if cycles is not None:
        result["battery_cycle_count"] = cycles
    return result


def network_quality(cfg):
    """TCP probes against the configured host, falling back to well-known hosts so one blocked
    target doesn't produce a false 'no internet'."""
    samples = max(1, min(5, int(cfg.get("network_probe_count", 3))))
    targets = [(cfg["network_check_host"], cfg["network_check_port"]),
               ("8.8.8.8", 443), ("1.1.1.1", 443), ("www.google.com", 443)]
    latencies, failures = [], 0
    for _ in range(samples):
        connected = False
        for host, port in targets:
            started = time.perf_counter()
            try:
                with socket.create_connection((host, port), timeout=3):
                    latencies.append((time.perf_counter() - started) * 1000)
                    connected = True
                    break
            except OSError:
                continue
        if not connected:
            failures += 1
            if not latencies:          # fully offline: stop early
                failures = samples
                break
    return {"network_ok": bool(latencies),
            "network_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else None,
            "network_loss_percent": round(failures * 100 / samples)}


def wifi_signal():
    """Wi-Fi signal strength (0-100) when connected over wireless."""
    try:
        if OS == "Windows":
            out = run(["netsh", "wlan", "show", "interfaces"], 10)
            sig = re.search(r"^\s*Signal\s*:\s*(\d+)%", out, re.M)
            ssid = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.M)
            if sig:
                return {"wifi_signal_percent": int(sig.group(1)),
                        "wifi_ssid": ssid.group(1).strip() if ssid else ""}
        elif OS == "Linux":
            out = run(["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL", "dev", "wifi"], 10)
            for line in out.splitlines():
                if line.startswith("*:"):
                    parts = line.split(":")
                    return {"wifi_signal_percent": int(parts[-1]),
                            "wifi_ssid": ":".join(parts[1:-1]).replace("\\", "")}
        elif OS == "Darwin":
            airport = ("/System/Library/PrivateFrameworks/Apple80211.framework/"
                       "Versions/Current/Resources/airport")
            out = run([airport, "-I"], 10)
            rssi = re.search(r"agrCtlRSSI:\s*(-?\d+)", out)
            ssid = re.search(r"\sSSID:\s*(.+)", out)
            if rssi:
                pct = max(0, min(100, 2 * (int(rssi.group(1)) + 100)))
                return {"wifi_signal_percent": pct, "wifi_ssid": ssid.group(1).strip() if ssid else ""}
    except (ValueError, OSError):
        pass
    return {}


def gpu_status():
    """NVIDIA GPUs via nvidia-smi (other vendors don't expose a portable CLI)."""
    if not shutil_which("nvidia-smi"):
        return []
    out = run(["nvidia-smi", "--query-gpu=name,utilization.gpu,temperature.gpu,memory.used,memory.total",
               "--format=csv,noheader,nounits"], 10)
    gpus = []
    for line in out.splitlines():
        p = [x.strip() for x in line.split(",")]
        if len(p) >= 5:
            try:
                gpus.append({"name": p[0], "util": float(p[1]), "temp": float(p[2]),
                             "mem_used_mb": float(p[3]), "mem_total_mb": float(p[4])})
            except ValueError:
                continue
    return gpus


def speed_test(cfg):
    """Small download + upload test against Cloudflare's public speed endpoints."""
    res = {"time": datetime.now().isoformat(timespec="seconds")}
    mb = max(1, min(25, int(cfg.get("speedtest_download_mb", 5))))
    try:
        req = urllib.request.Request(f"https://speed.cloudflare.com/__down?bytes={mb * 1000000}",
                                     headers={"User-Agent": "DeviceWatch"})
        started, total = time.perf_counter(), 0
        with urllib.request.urlopen(req, timeout=30) as r:
            while True:
                chunk = r.read(1 << 16)
                if not chunk:
                    break
                total += len(chunk)
        secs = max(time.perf_counter() - started, 0.001)
        res["download_mbps"] = round(total * 8 / secs / 1e6, 1)
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"
        return res
    try:
        data = b"0" * 1000000
        req = urllib.request.Request("https://speed.cloudflare.com/__up", data=data,
                                     headers={"User-Agent": "DeviceWatch",
                                              "Content-Type": "application/octet-stream"})
        started = time.perf_counter()
        urllib.request.urlopen(req, timeout=30).read()
        secs = max(time.perf_counter() - started, 0.001)
        res["upload_mbps"] = round(len(data) * 8 / secs / 1e6, 1)
    except Exception:
        pass
    return res


def backup_status(paths, max_age_days):
    checks = []
    now = time.time()
    for raw_path in paths:
        path = Path(os.path.expandvars(str(raw_path))).expanduser()
        candidates = []
        try:
            if path.is_dir():
                candidates.extend(item.stat().st_mtime for item in path.iterdir())
            elif path.is_file():
                candidates = [path.stat().st_mtime]
        except OSError:
            pass
        newest = max(candidates) if candidates else None
        age_days = round((now - newest) / 86400, 1) if newest is not None else None
        checks.append({"path": str(path), "age_days": age_days,
                       "fresh": age_days is not None and age_days <= max_age_days,
                       "last_backup": datetime.fromtimestamp(newest).isoformat(timespec="seconds")
                       if newest is not None else None})
    return checks


def disk_health_status():
    info = {"available": False, "devices": [],
            "checked": datetime.now().isoformat(timespec="seconds")}
    if OS == "Windows":
        out = ps("$d=Get-PhysicalDisk | Select-Object FriendlyName,HealthStatus,OperationalStatus,Temperature;"
                 "if($d){$d | ConvertTo-Json -Compress}", timeout=45).strip()
        if out:
            try:
                devices = json.loads(out)
                devices = devices if isinstance(devices, list) else [devices]
                for device in devices:
                    health = str(device.get("HealthStatus") or "Unknown")
                    operational = device.get("OperationalStatus") or []
                    if not isinstance(operational, list):
                        operational = [operational]
                    healthy = (True if health.lower() == "healthy" and all(
                        str(state).lower() in ("ok", "healthy") for state in operational) else
                        False if health.lower() in ("warning", "unhealthy", "lost communication") or
                        any(str(state).lower() not in ("ok", "healthy") for state in operational) else None)
                    info["devices"].append({"name": device.get("FriendlyName") or "Physical disk",
                                             "status": health, "healthy": healthy,
                                             "temperature_c": device.get("Temperature")})
                info["available"] = bool(info["devices"])
            except (ValueError, TypeError):
                pass
    if not info["available"] and shutil_which("smartctl"):
        scan = run(["smartctl", "--scan-open"], 30)
        for line in scan.splitlines():
            spec = line.split("#", 1)[0].split()
            if not spec:
                continue
            out = run(["smartctl", "-j", "-H", "-A", *spec], 30)
            try:
                data = json.loads(out)
            except (ValueError, TypeError):
                continue
            passed = data.get("smart_status", {}).get("passed")
            nvme = data.get("nvme_smart_health_information_log", {})
            attributes = data.get("ata_smart_attributes", {}).get("table", [])
            problems = []
            for attr in attributes:
                name = str(attr.get("name", "")).lower()
                raw = attr.get("raw", {}).get("value", 0)
                if any(term in name for term in ("reallocated", "pending", "uncorrectable")) and raw:
                    problems.append(f"{attr.get('name')}: {raw}")
            if nvme.get("critical_warning"):
                problems.append(f"NVMe critical warning: {nvme['critical_warning']}")
            if nvme.get("media_errors"):
                problems.append(f"NVMe media errors: {nvme['media_errors']}")
            has_health_data = passed is not None or bool(nvme)
            healthy = False if problems or passed is False else True if has_health_data else None
            info["devices"].append({"name": data.get("model_name") or spec[0],
                                     "status": "Healthy" if healthy is True else
                                     "Warning" if healthy is False else "Unknown",
                                     "healthy": healthy, "problems": problems,
                                     "temperature_c": data.get("temperature", {}).get("current")})
        info["available"] = bool(info["devices"])
    if not info["available"]:
        info["note"] = "Install smartmontools and run with disk access to enable SMART health checks."
    return info


def app_update_status():
    info = {"available": False, "apps": [],
            "checked": datetime.now().isoformat(timespec="seconds")}
    if OS == "Windows" and shutil_which("winget"):
        out = run(["winget", "upgrade", "--include-unknown", "--accept-source-agreements",
                   "--disable-interactivity"], 180)
        lines = out.splitlines()
        header = next((i for i, line in enumerate(lines) if "Name" in line and "Id" in line and "Version" in line), None)
        if header is not None:
            info["available"] = True
            for line in lines[header + 1:]:
                if not line.strip() or set(line.strip()) <= {"-", " "}:
                    continue
                columns = re.split(r"\s{2,}", line.strip())
                if len(columns) >= 4:
                    info["apps"].append({"name": columns[0], "id": columns[1],
                                         "current": columns[2], "latest": columns[3]})
    elif OS == "Darwin" and shutil_which("brew"):
        out = run(["brew", "outdated", "--json=v2"], 180)
        try:
            data = json.loads(out)
            for kind in ("formulae", "casks"):
                for item in data.get(kind, []):
                    installed = item.get("installed_versions") or []
                    info["apps"].append({"name": item.get("name") or item.get("token"),
                                         "current": installed[0] if installed else "",
                                         "latest": item.get("current_version", "")})
            info["available"] = True
        except (ValueError, TypeError, IndexError):
            pass
    elif OS == "Linux":
        if shutil_which("flatpak"):
            out = run(["flatpak", "remote-ls", "--updates", "--columns=application,name,version"], 90)
            info["available"] = True
            for line in out.splitlines():
                columns = line.split("\t") if "\t" in line else re.split(r"\s{2,}", line.strip())
                if columns and columns[0] and columns[0].lower() not in (
                        "application", "no updates", "no matches found."):
                    info["apps"].append({"name": columns[1] if len(columns) > 1 else columns[0],
                                         "id": columns[0], "latest": columns[-1]})
        if shutil_which("snap"):
            out = run(["snap", "refresh", "--list"], 90)
            info["available"] = True
            for line in out.splitlines()[1:]:
                columns = re.split(r"\s{2,}", line.strip())
                if len(columns) >= 3:
                    info["apps"].append({"name": columns[0], "current": columns[1], "latest": columns[2]})
    info["count"] = len(info["apps"])
    return info


def thermal_status():
    info = {"fans": [], "throttle_count": None, "cpu_speed_limit_percent": None}
    if hasattr(psutil, "sensors_fans"):
        try:
            for name, fans in psutil.sensors_fans().items():
                for fan in fans:
                    info["fans"].append({"name": fan.label or name, "rpm": fan.current})
        except (OSError, RuntimeError):
            pass
    if OS == "Windows" and not info["fans"]:
        out = ps("$f=Get-CimInstance Win32_Fan | Select-Object Name,DesiredSpeed,Status;"
                 "if($f){$f | ConvertTo-Json -Compress}", timeout=20).strip()
        if out:
            try:
                fans = json.loads(out)
                fans = fans if isinstance(fans, list) else [fans]
                info["fans"] = [{"name": fan.get("Name") or "System fan",
                                 "rpm": fan.get("DesiredSpeed")} for fan in fans]
            except (ValueError, TypeError):
                pass
    elif OS == "Linux":
        counts = []
        for path in Path("/sys/devices/system/cpu").glob("cpu*/thermal_throttle/*_throttle_count"):
            try:
                counts.append(int(path.read_text().strip()))
            except (OSError, ValueError):
                continue
        if counts:
            info["throttle_count"] = sum(counts)
    elif OS == "Darwin":
        out = run(["pmset", "-g", "therm"], 10)
        match = re.search(r"CPU_Speed_Limit\s*[:=]\s*(\d+)", out)
        if match:
            info["cpu_speed_limit_percent"] = int(match.group(1))
    return info


def usb_devices():
    """Names of USB devices currently attached."""
    names = set()
    try:
        if OS == "Windows":
            out = ps(r"Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'USB\*' } | "
                     r"ForEach-Object { $_.FriendlyName + ' [' + $_.InstanceId + ']' }", 30)
            for line in out.splitlines():
                line = line.strip()
                if line and "root hub" not in line.lower() and "generic usb hub" not in line.lower():
                    names.add(line)
        elif OS == "Linux":
            base = Path("/sys/bus/usb/devices")
            if base.is_dir():
                for d in base.iterdir():
                    try:
                        prod = (d / "product").read_text().strip()
                        vid = (d / "idVendor").read_text().strip()
                        pid = (d / "idProduct").read_text().strip()
                    except OSError:
                        continue
                    if "root hub" not in prod.lower():
                        names.add(f"{prod} ({vid}:{pid})")
        elif OS == "Darwin":
            def walk(items):
                for it in items or []:
                    if isinstance(it, dict):
                        if "vendor_id" in it or "product_id" in it:
                            names.add(f"{it.get('_name', 'USB device')} "
                                      f"({it.get('vendor_id', '')}:{it.get('product_id', '')})")
                        walk(it.get("_items"))
            out = run(["system_profiler", "SPUSBDataType", "-json"], 30)
            if out.strip():
                walk(json.loads(out).get("SPUSBDataType"))
    except (ValueError, OSError):
        pass
    return names


def failed_logins_last_hour():
    """Failed sign-in attempts in the last hour, or None if the OS won't tell us."""
    try:
        if OS == "Windows":
            q = "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 3600000]]]"
            r = subprocess.run(["wevtutil", "qe", "Security", f"/q:{q}", "/f:xml", "/c:500"],
                               capture_output=True, text=True, errors="replace", timeout=30,
                               creationflags=CREATE_NO_WINDOW)
            return r.stdout.count("<Event ") if r.returncode == 0 else None   # needs admin
        if OS == "Linux" and shutil_which("journalctl"):
            out = run(["journalctl", "--since", "1 hour ago", "--no-pager", "-q"], 30)
            if out.strip():
                return len(re.findall(r"Failed password|authentication failure|FAILED LOGIN", out))
    except Exception:
        pass
    return None


def boot_analysis():
    info = {"boot_seconds": None, "slowest": [], "startup_items": []}
    try:
        if OS == "Windows":
            out = ps("(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Diagnostics-Performance/Operational';Id=100} "
                     "-MaxEvents 1 -ErrorAction SilentlyContinue | ForEach-Object { ([xml]$_.ToXml()).Event.EventData.Data | "
                     "Where-Object { $_.Name -eq 'BootTime' } | ForEach-Object { $_.'#text' } })", 30).strip()
            if out.isdigit():
                info["boot_seconds"] = round(int(out) / 1000, 1)
            raw = ps("Get-CimInstance Win32_StartupCommand | Select-Object Name,Command | ConvertTo-Json -Compress", 30).strip()
            if raw:
                data = json.loads(raw)
                data = data if isinstance(data, list) else [data]
                info["startup_items"] = sorted({str(x.get("Name")) for x in data if x.get("Name")})
        elif OS == "Linux":
            total = run(["systemd-analyze"], 20)
            match = re.search(r"=\s*(?:(\d+)min\s*)?([\d.]+)s", total)
            if match:
                info["boot_seconds"] = round(int(match.group(1) or 0) * 60 + float(match.group(2)), 1)
            for line in run(["systemd-analyze", "blame", "--no-pager"], 20).splitlines()[:8]:
                parts = line.strip().rsplit(None, 1)
                if len(parts) == 2:
                    info["slowest"].append({"name": parts[1], "time": parts[0]})
        if not info["startup_items"]:
            info["startup_items"] = sorted(autostart_entries())[:30]
    except (ValueError, OSError, TypeError):
        pass
    return info


# ----------------------------------------------------------- safe auto-fixes
def browser_cache_dirs():
    h = Path.home()
    dirs = []
    if OS == "Windows":
        local = Path(os.environ.get("LOCALAPPDATA", h / "AppData" / "Local"))
        for base in (local / "Google/Chrome/User Data", local / "Microsoft/Edge/User Data",
                     local / "BraveSoftware/Brave-Browser/User Data"):
            if base.is_dir():
                for prof in base.iterdir():
                    if prof.name == "Default" or prof.name.startswith("Profile "):
                        dirs += [prof / "Cache", prof / "Code Cache", prof / "GPUCache"]
        ff = local / "Mozilla/Firefox/Profiles"
        if ff.is_dir():
            dirs += [p / "cache2" for p in ff.iterdir()]
    elif OS == "Darwin":
        lib = h / "Library/Caches"
        dirs += [lib / "Google/Chrome", lib / "Microsoft Edge", lib / "Firefox/Profiles"]
    else:
        cache = h / ".cache"
        dirs += [cache / n for n in ("google-chrome", "chromium", "microsoft-edge",
                                     "BraveSoftware", "mozilla/firefox")]
    return [d for d in dirs if d.is_dir()]


def delete_files_in(dirs):
    """Delete regular files under dirs. Never follows symlinks. Returns bytes freed."""
    freed = 0
    for d in dirs:
        for f in d.rglob("*"):
            try:
                if f.is_file() and not f.is_symlink():
                    size = f.stat().st_size
                    f.unlink()
                    freed += size
            except OSError:
                continue
    return freed


def empty_recycle_bin():
    if OS == "Windows":
        ps("Clear-RecycleBin -Force -ErrorAction SilentlyContinue", 60)
        return "Recycle Bin emptied."
    trash = Path.home() / (".Trash" if OS == "Darwin" else ".local/share/Trash/files")
    if not trash.is_dir():
        return "Trash is already empty."
    freed = 0
    for child in trash.iterdir():
        try:
            if child.is_dir() and not child.is_symlink():
                freed += sum(f.stat().st_size for f in child.rglob("*") if f.is_file())
                shutil.rmtree(child, ignore_errors=True)
            else:
                freed += child.stat().st_size
                child.unlink()
        except OSError:
            continue
    return f"Trash emptied ({round(freed / 1024 ** 2, 1)} MB)."


def flush_dns():
    if OS == "Windows":
        run(["ipconfig", "/flushdns"], 15)
    elif OS == "Darwin":
        run(["dscacheutil", "-flushcache"], 15)
    elif shutil_which("resolvectl"):
        run(["resolvectl", "flush-caches"], 15)
    else:
        run(["systemd-resolve", "--flush-caches"], 15)
    return "DNS cache flushed."


# ----------------------------------------------------------------- services
def service_state(name):
    if OS == "Windows":
        out = ps(f"(Get-Service -Name '{name}' -ErrorAction SilentlyContinue).Status", 20).strip().lower()
        return "running" if out == "running" else "stopped" if out == "stopped" else "unknown"
    if OS == "Linux":
        out = run(["systemctl", "is-active", name], 15).strip()
        return "running" if out == "active" else "stopped" if out in ("inactive", "failed") else "unknown"
    return "unknown"


def restart_service(name):
    if OS == "Windows":
        ps(f"Start-Service -Name '{name}' -ErrorAction SilentlyContinue", 60)
    elif OS == "Linux":
        run(["systemctl", "restart", name], 60)
        if service_state(name) != "running":
            run(["sudo", "-n", "systemctl", "restart", name], 60)
    time.sleep(3)
    return service_state(name) == "running"


# ------------------------------------------------------------------- history
def read_history(hours, max_points=0):
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat(timespec="seconds")
    rows = []
    try:
        with open(HISTORY_PATH) as f:
            for line in f:
                if line.startswith('{"t": "') and line[7:26] < cutoff:
                    continue
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return []
    if max_points and len(rows) > max_points:
        step = len(rows) / max_points
        rows = [max(rows[int(i * step):int((i + 1) * step)] or [rows[-1]], key=lambda r: r.get("cpu") or 0)
                for i in range(max_points)]
    return rows


def prune_history(days):
    try:
        if not HISTORY_PATH.exists() or HISTORY_PATH.stat().st_size < 1_000_000:
            return
        rows = read_history(days * 24)
        tmp = HISTORY_PATH.with_suffix(".tmp")
        tmp.write_text("".join(json.dumps(r) + "\n" for r in rows))
        tmp.replace(HISTORY_PATH)
    except OSError:
        pass


def find_spikes(hours, cfg):
    """Group consecutive high-CPU / high-RAM samples into events and say which apps caused them."""
    gap = max(cfg["interval_seconds"], 30) * 2.5
    events, cur = [], None
    for r in read_history(hours):
        cpu, ram = r.get("cpu") or 0, r.get("ram") or 0
        if cpu < cfg["cpu_percent"] and ram < cfg["ram_percent"]:
            continue
        try:
            ts = datetime.fromisoformat(r["t"])
        except (KeyError, ValueError):
            continue
        if cur and (ts - cur["_last"]).total_seconds() <= gap:
            cur["end"], cur["_last"] = r["t"], ts
            if cpu + ram > cur["_peak"]:
                cur.update(_peak=cpu + ram, top_cpu=r.get("tc") or [], top_mem=r.get("tm") or [])
            cur["peak_cpu"], cur["peak_ram"] = max(cur["peak_cpu"], cpu), max(cur["peak_ram"], ram)
        else:
            cur = {"start": r["t"], "end": r["t"], "_last": ts, "_peak": cpu + ram,
                   "peak_cpu": cpu, "peak_ram": ram,
                   "top_cpu": r.get("tc") or [], "top_mem": r.get("tm") or []}
            events.append(cur)
    for e in events:
        e.pop("_last", None)
        e.pop("_peak", None)
    return events[::-1][:100]


def sanitize_status(d):
    """Validate a status pushed by another computer (multi-device hub)."""
    def num(v):
        return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None
    issues = []
    for i in (d.get("issues") or [])[:20]:
        if isinstance(i, dict):
            issues.append({"severity": str(i.get("severity", "info"))[:12],
                           "message": str(i.get("message", ""))[:300]})
    return {"name": str(d.get("name", "unknown"))[:60], "os": str(d.get("os", ""))[:80],
            "score": num(d.get("score")), "cpu": num(d.get("cpu")), "ram": num(d.get("ram")),
            "disk": num(d.get("disk")), "battery": num(d.get("battery")),
            "time": str(d.get("time", ""))[:30], "issues": issues}


class Monitor:
    def __init__(self, cfg):
        self.cfg = cfg
        self.cpu_hist = deque(maxlen=max(1, cfg["cpu_sustained_samples"]))
        self.last_alert = {}
        self.latest = {"metrics": {}, "issues": [], "score": 100}
        self.err_count = 0
        self.last_err_scan = 0
        self.sticky, self.sec_issues, self.sec_info = {}, [], {}
        self.update_issues, self.update_info = [], {}
        self.disk_info, self.disk_issues = {}, []
        self.app_info, self.app_issues = {}, []
        self.backup_info, self.backup_issues = [], []
        self.last_throttle_count = None
        self.battery_health_info, self.last_battery_health_check = {}, 0
        self.hash_cache, self.vt_cache, self.vt_budget = {}, {}, 0
        self._cache = {}
        self.prev_io = None
        self.disk_busy_hist = deque(maxlen=4)
        self.speed_hist, self.speed_issues = deque(maxlen=50), []
        self.conn_info, self.conn_issues = {}, []
        self.integrity_info, self.integrity_issues, self.integrity_current = {}, [], {}
        self.canary_info, self.canary_issues = {}, []
        self.usb_known, self.usb_current = None, []
        self.login_count, self.login_issues = None, []
        self.boot_info, self.boot_issues = {}, []
        self.leak_hist, self.leak_issues = {}, []
        self.svc_info, self.svc_issues, self.svc_restarts = [], [], {}
        self.devices = {}                 # multi-device hub: name -> {"received": ts, **status}
        self.dashboard_url = None
        try:
            for line in SPEED_PATH.read_text().splitlines()[-50:]:
                self.speed_hist.append(json.loads(line))
        except (OSError, ValueError):
            pass
        psutil.cpu_percent(None)
        for p in psutil.process_iter():
            try:
                p.cpu_percent(None)
            except psutil.Error:
                pass

    def cached(self, key, ttl, fn):
        now = time.monotonic()
        hit = self._cache.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
        val = fn()
        self._cache[key] = (now, val)
        return val

    # ------------------------------------------------------------ collection
    def collect(self):
        c = self.cfg
        m = {"time": datetime.now().isoformat(timespec="seconds"),
             "host": platform.node(), "os": f"{OS} {platform.release()}"}
        issues = []

        def add(sev, key, msg, fix):
            issues.append({"severity": sev, "key": key, "message": msg, "fix": fix})

        # CPU
        cpu = psutil.cpu_percent(interval=1)
        self.cpu_hist.append(cpu)
        m["cpu_percent"] = cpu
        m["cpu_cores"] = psutil.cpu_count()
        if len(self.cpu_hist) == self.cpu_hist.maxlen and min(self.cpu_hist) >= c["cpu_percent"]:
            add("warning", "cpu", f"CPU has been above {c['cpu_percent']}% for a while ({cpu:.0f}% now).",
                "Check the top processes below; close or restart the heavy one. Scan for malware if it's unfamiliar.")

        # Top processes
        procs = []
        ncpu = psutil.cpu_count() or 1
        for p in psutil.process_iter(["name", "cpu_percent", "memory_percent"]):
            i = p.info
            if i.get("name") and i["name"] != "System Idle Process":
                procs.append({"pid": p.pid, "name": i["name"],
                              "cpu": round((i["cpu_percent"] or 0) / ncpu, 1),
                              "mem": round(i["memory_percent"] or 0, 1)})
        m["top_cpu"] = sorted(procs, key=lambda x: x["cpu"], reverse=True)[:5]
        m["top_mem"] = sorted(procs, key=lambda x: x["mem"], reverse=True)[:5]

        # Memory
        vm = psutil.virtual_memory()
        m["ram_percent"] = vm.percent
        m["ram_used_gb"], m["ram_total_gb"] = gb(vm.used), gb(vm.total)
        if vm.percent >= c["ram_percent"]:
            top = m["top_mem"][0]["name"] if m["top_mem"] else "unknown"
            add("critical" if vm.percent >= 95 else "warning", "ram",
                f"Memory is at {vm.percent:.0f}% ({gb(vm.used)} of {gb(vm.total)} GB). Biggest user: {top}.",
                "Close unused apps/browser tabs, restart the memory-heavy app, or add more RAM.")
        sw = psutil.swap_memory()
        if sw.total and sw.percent >= c["swap_percent"]:
            add("warning", "swap", f"Swap/pagefile is {sw.percent:.0f}% full - the system is struggling for memory.",
                "Free memory by closing apps; consider a restart.")

        # Disks (space)
        disks = []
        for part in psutil.disk_partitions(all=False):
            if "cdrom" in part.opts or not part.fstype or part.fstype == "squashfs" \
                    or part.mountpoint.startswith("/snap"):
                continue
            try:
                u = psutil.disk_usage(part.mountpoint)
            except Exception:
                continue
            disks.append({"mount": part.mountpoint, "percent": u.percent,
                          "free_gb": gb(u.free), "total_gb": gb(u.total)})
            if u.percent >= c["disk_percent"] or gb(u.free) < c["disk_free_gb_min"]:
                add("critical" if u.percent >= 95 else "warning", f"disk:{part.mountpoint}",
                    f"Disk {part.mountpoint} is {u.percent:.0f}% full ({gb(u.free)} GB free).",
                    "Empty the recycle bin/downloads, uninstall unused apps, or run a disk cleanup.")
        m["disks"] = disks

        # Disk I/O and network throughput (rates since the previous check)
        try:
            now_t, dio, nio = time.time(), psutil.disk_io_counters(), psutil.net_io_counters()
            if self.prev_io and dio and nio and self.prev_io[1] and self.prev_io[2]:
                dt = now_t - self.prev_io[0]
                pd, pn = self.prev_io[1], self.prev_io[2]
                if dt > 0:
                    m["disk_read_mbps"] = round((dio.read_bytes - pd.read_bytes) / dt / 1048576, 2)
                    m["disk_write_mbps"] = round((dio.write_bytes - pd.write_bytes) / dt / 1048576, 2)
                    m["net_down_mbps"] = round((nio.bytes_recv - pn.bytes_recv) * 8 / dt / 1e6, 2)
                    m["net_up_mbps"] = round((nio.bytes_sent - pn.bytes_sent) * 8 / dt / 1e6, 2)
                    if hasattr(dio, "busy_time") and hasattr(pd, "busy_time"):
                        busy = min(100.0, (dio.busy_time - pd.busy_time) / (dt * 1000) * 100)
                        m["disk_busy_percent"] = round(busy, 1)
                        self.disk_busy_hist.append(busy)
                        if len(self.disk_busy_hist) == self.disk_busy_hist.maxlen and \
                                min(self.disk_busy_hist) >= c["disk_busy_warn_percent"]:
                            add("warning", "disk:io", "The disk has been almost 100% busy for several minutes.",
                                "Check which processes read/write heavily (indexing, backups, updates, antivirus scans).")
            self.prev_io = (now_t, dio, nio)
        except (OSError, AttributeError):
            pass

        # Temperature (Linux exposes this via psutil; Windows/macOS generally don't)
        if hasattr(psutil, "sensors_temperatures"):
            try:
                temps = [t.current for ts in psutil.sensors_temperatures().values()
                         for t in ts if t.current]
            except Exception:
                temps = []
            if temps:
                m["max_temp_c"] = round(max(temps), 1)
                if max(temps) >= c["cpu_temp_c"]:
                    add("critical", "temp", f"Device is running hot ({max(temps):.0f} C).",
                        "Clean vents/fans, use a hard flat surface, close heavy apps, check thermal paste if recurring.")
        thermal = self.cached("thermal", 120 if OS == "Windows" else 0, thermal_status)
        m["fan_speeds"] = thermal["fans"]
        if thermal["throttle_count"] is not None:
            m["throttle_count"] = thermal["throttle_count"]
            if self.last_throttle_count is not None and thermal["throttle_count"] > self.last_throttle_count:
                add("warning", "thermal:throttle", "CPU thermal throttling activity increased since the last check.",
                    "Clear vents, improve airflow, and reduce sustained CPU load; verify cooling if it continues.")
            self.last_throttle_count = thermal["throttle_count"]
        if thermal["cpu_speed_limit_percent"] is not None:
            m["cpu_speed_limit_percent"] = thermal["cpu_speed_limit_percent"]
            if thermal["cpu_speed_limit_percent"] < 80:
                add("warning", "thermal:limit",
                    f"The system reports CPU speed limited to {thermal['cpu_speed_limit_percent']}%.",
                    "Check thermal conditions and power settings; macOS may also apply limits during high temperature.")

        # GPU
        gpus = self.cached("gpu", 25, gpu_status)
        m["gpus"] = gpus
        for g in gpus:
            if g["temp"] >= c["gpu_temp_c"]:
                add("warning", "gpu:temp", f"GPU {g['name']} is running hot ({g['temp']:.0f} C).",
                    "Check case airflow and GPU fans; lower graphics load or clean dust.")

        # Battery
        bat = psutil.sensors_battery() if hasattr(psutil, "sensors_battery") else None
        if bat:
            m["battery_percent"] = round(bat.percent)
            m["battery_plugged"] = bool(bat.power_plugged)
            if time.monotonic() - self.last_battery_health_check >= 1800:
                self.battery_health_info = battery_health()
                self.last_battery_health_check = time.monotonic()
            m.update(self.battery_health_info)
            if not bat.power_plugged and bat.percent <= c["battery_low_percent"]:
                add("warning", "battery", f"Battery is low ({bat.percent:.0f}%) and not charging.",
                    "Plug in your charger.")
            if m.get("battery_health_percent") is not None and \
                    m["battery_health_percent"] <= c["battery_health_warn_percent"]:
                add("warning", "battery:health",
                    f"Battery health is low ({m['battery_health_percent']}% capacity; {m['battery_wear_percent']}% wear).",
                    "Consider replacing the battery if runtime is insufficient or the device reports battery service is needed.")

        # Network reachability and quality (bounded TCP probes) + Wi-Fi
        network = network_quality(c)
        m.update(network)
        if not m["network_ok"]:
            add("warning", "network", "No internet connectivity.",
                "Check Wi-Fi/cable, restart your router, or run your OS network troubleshooter.")
        elif m["network_loss_percent"] >= 33 or (
                m["network_latency_ms"] is not None and m["network_latency_ms"] >= c["network_latency_warn_ms"]):
            add("notice", "network:quality",
                f"Network quality is degraded ({m['network_latency_ms']} ms average, {m['network_loss_percent']}% probe loss).",
                "Check Wi-Fi signal, local network congestion, or the configured network check host.")
        m.update(self.cached("wifi", 60, wifi_signal))
        if m.get("wifi_signal_percent") is not None and m["wifi_signal_percent"] <= c["wifi_signal_warn_percent"]:
            add("notice", "wifi:weak", f"Wi-Fi signal is weak ({m['wifi_signal_percent']}%).",
                "Move closer to the router, reduce obstacles, or switch to the 5 GHz band / a cable.")

        # Uptime
        up_days = (time.time() - psutil.boot_time()) / 86400
        m["uptime_days"] = round(up_days, 1)
        if up_days >= c["uptime_days_warn"]:
            add("info", "uptime", f"Up for {up_days:.0f} days without a restart.",
                "Restart to apply updates and clear memory leaks.")

        # System errors (hourly, best-effort)
        if c["scan_system_errors"] and time.time() - self.last_err_scan > 3600:
            self.err_count = self.count_system_errors()
            self.last_err_scan = time.time()
        if c["scan_system_errors"] and self.err_count is not None:
            m["system_errors_last_hour"] = self.err_count
            if self.err_count >= c["system_errors_per_hour_warn"]:
                add("warning", "syserrors", f"{self.err_count} system errors logged in the last hour.",
                    "Windows: Event Viewer > System. Linux: journalctl -p 3 -xb. Look for repeating drivers/services.")

        # Findings from background scans
        issues += self.sec_issues + self.update_issues
        issues += self.disk_issues + self.app_issues + self.backup_issues
        issues += self.conn_issues + self.speed_issues + self.integrity_issues + self.canary_issues
        issues += self.login_issues + self.boot_issues + self.leak_issues + self.svc_issues
        issues += self.hub_issues()
        issues += [v[1] for _, v in list(self.sticky.items()) if v[0] > time.time()]
        m["security"], m["updates"] = self.sec_info, self.update_info
        m["disk_health"], m["app_updates"], m["backups"] = self.disk_info, self.app_info, self.backup_info
        m["connections"], m["integrity"], m["canary"] = self.conn_info, self.integrity_info, self.canary_info
        m["usb_devices"], m["failed_logins"] = sorted(self.usb_current), self.login_count
        m["boot"], m["services"] = self.boot_info, self.svc_info
        m["speedtests"] = list(self.speed_hist)[-10:]

        # Health score
        penalty = {"critical": 25, "warning": 10, "notice": 5, "info": 3}
        score = max(0, 100 - sum(penalty.get(i["severity"], 3) for i in issues))
        return {"metrics": m, "issues": issues, "score": score}

    @staticmethod
    def count_system_errors():
        try:
            if OS == "Windows":
                q = "*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= 3600000]]]"
                out = subprocess.run(["wevtutil", "qe", "System", f"/q:{q}", "/f:xml", "/c:200"],
                                     capture_output=True, text=True, errors="replace", timeout=30).stdout
                return out.count("<Event ")
            if OS == "Linux":
                out = subprocess.run(["journalctl", "-p", "3", "--since", "1 hour ago", "--no-pager", "-q"],
                                     capture_output=True, text=True, errors="replace", timeout=30).stdout
                return len([l for l in out.splitlines() if l.strip()])
        except Exception:
            pass
        return None

    # -------------------------------------------------------------- security
    def load_blocklist(self):
        try:
            return {l.split()[0].lower() for l in BLOCKLIST_PATH.read_text().splitlines()
                    if l.strip() and not l.startswith("#")}
        except OSError:
            return set()

    def load_bad_ips(self):
        try:
            return {l.split()[0] for l in BAD_IPS_PATH.read_text().splitlines()
                    if l.strip() and not l.startswith("#")}
        except OSError:
            return set()

    def hash_of(self, path):
        try:
            st = os.stat(path)
            if st.st_size > 200 * 1024 * 1024:
                return None
            key = (st.st_mtime, st.st_size)
            hit = self.hash_cache.get(path)
            if hit and hit[0] == key:
                return hit[1]
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            self.hash_cache[path] = (key, h.hexdigest())
            return h.hexdigest()
        except OSError:
            return None

    def vt_lookup(self, sha):
        """Ask VirusTotal about a file HASH (the file itself is never uploaded). None = unknown."""
        key = self.cfg["virustotal_api_key"]
        if not key:
            return None
        if sha in self.vt_cache:
            return self.vt_cache[sha]
        if self.vt_budget <= 0:
            return None
        self.vt_budget -= 1
        try:
            req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha}", headers={"x-apikey": key})
            with urllib.request.urlopen(req, timeout=15) as r:
                res = json.load(r)["data"]["attributes"]["last_analysis_stats"].get("malicious", 0)
        except urllib.error.HTTPError:
            res = None          # 404: VirusTotal has never seen this file
        except Exception:
            return None
        self.vt_cache[sha] = res
        return res

    def security_scan(self):
        c = self.cfg
        if not c["scan_malware"]:
            return
        issues, info, reported = [], {}, set()
        self.vt_budget = 4      # free VirusTotal keys allow ~4 lookups/minute

        def add(sev, key, msg, fix, sticky=False):
            if key in reported:
                return
            reported.add(key)
            issue = {"severity": sev, "key": key, "message": msg, "fix": fix}
            if sticky:
                self.sticky[key] = (time.time() + 86400, issue)
            else:
                issues.append(issue)

        # 1) Protection status
        p = protection_status()
        info["av_ok"] = p["av_ok"]
        bits = []
        if p["av_names"]:
            bits.append("AV: " + ", ".join(p["av_names"]))
        if p["firewall_ok"] is not None:
            bits.append("Firewall " + ("on" if p["firewall_ok"] else "OFF"))
        if p["av_ok"] is False:
            add("critical", "mal:av", "No active antivirus / real-time protection detected.",
                "Turn on Windows Security real-time protection (or Gatekeeper on macOS), or install a reputable antivirus.")
        if p["sig_age"] is not None and p["sig_age"] > c["signature_max_age_days"]:
            add("warning", "mal:sigs", f"Antivirus definitions are {p['sig_age']} days old.",
                "Open Windows Security > Virus & threat protection > Check for updates.")
        if p["firewall_ok"] is False:
            add("info" if OS == "Linux" else "warning", "mal:firewall", "Firewall is turned off.",
                "Turn the firewall back on (Windows Security > Firewall; macOS Settings > Network > Firewall; Linux: sudo ufw enable).")
        for n in p["notes"]:
            add("critical", "mal:note:" + n[:30], n, "Re-enable it unless you turned it off deliberately.")

        # 2) Suspicious processes
        risky = RISKY_DIRS.get(OS, ())
        winroot = (os.environ.get("SystemRoot") or "c:\\windows").lower()
        ignore = {n.lower() for n in c["ignore_process_names"]}
        blocklist = self.load_blocklist()
        suspects = 0
        for pr in psutil.process_iter(["name", "exe"]):
            try:
                name, exe = pr.info["name"] or "", pr.info["exe"] or ""
                lname = name.lower()
                if lname in ignore:
                    continue
                lexe = exe.lower().replace("/", "\\") if OS == "Windows" else exe.lower()
                reasons, sev = [], "warning"
                if any(m in lname for m in MINER_NAMES):
                    reasons.append("known crypto-miner / credential-theft tool")
                    sev = "critical"
                else:
                    try:
                        cmd = " ".join(pr.cmdline()).lower()
                    except psutil.Error:
                        cmd = ""
                    if "stratum+tcp" in cmd or "stratum+ssl" in cmd or "--donate-level" in cmd:
                        reasons.append("crypto-mining command line")
                        sev = "critical"
                if OS == "Windows" and lname in WIN_SYSTEM_PROCS and lexe and not lexe.startswith(winroot):
                    reasons.append("fake Windows system process (running from the wrong location)")
                    sev = "critical"
                if lexe and any(d in lexe for d in risky) and "/tmp/.mount_" not in lexe:
                    reasons.append(f"running from a risky folder ({exe})")
                sha = self.hash_of(exe) if (exe and (blocklist or reasons)) else None
                if sha and sha in blocklist:
                    reasons.append("matches your malware-hash blocklist")
                    sev = "critical"
                if reasons and sha:
                    vt = self.vt_lookup(sha)
                    if vt is not None and vt >= 3:
                        reasons.append(f"flagged by {vt} VirusTotal engines")
                        sev = "critical"
                    elif vt == 0 and sev == "warning":
                        reasons = []     # known-clean file, just in an unusual folder
                if reasons:
                    suspects += 1
                    add(sev, f"mal:proc:{lname}", f"Suspicious process '{name}' (PID {pr.pid}): {'; '.join(reasons)}.",
                        MALWARE_FIX)
            except (psutil.Error, OSError):
                continue
        bits.append(f"{suspects} suspicious process(es)")

        # 3) New startup/persistence items + hosts-file tampering (compared to a saved baseline)
        cur = autostart_entries()
        hosts = (Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
                 if OS == "Windows" else Path("/etc/hosts"))
        with STATE_LOCK:
            st = load_state()
            if "autostart" in st:
                for item in sorted(cur - set(st["autostart"])):
                    add("warning", "mal:startup:" + item[:80], f"New program set to run automatically: {item}",
                        "If you didn't just install something, remove it (Windows: Task Manager > Startup / Task Scheduler) and run a full scan.",
                        sticky=True)
            else:
                logging.info("Security baseline created (%d startup items recorded).", len(cur))
            st["autostart"] = sorted(cur)
            try:
                hh = hashlib.sha256(hosts.read_bytes()).hexdigest()
                if st.get("hosts") and st["hosts"] != hh:
                    add("warning", "mal:hosts", "Your hosts file was modified (malware uses this to redirect websites).",
                        f"Open {hosts} and remove entries you don't recognise.", sticky=True)
                st["hosts"] = hh
            except OSError:
                pass
            save_state(st)

        info["summary"] = " | ".join(bits)
        info["suspicious"] = suspects
        info["last_scan"] = datetime.now().isoformat(timespec="seconds")
        self.sec_info, self.sec_issues = info, issues

    def connection_scan(self):
        """Open ports (new listeners) and suspicious outbound connections."""
        c = self.cfg
        if not (c.get("scan_open_ports", True) or c.get("watch_outbound", True)):
            self.conn_info, self.conn_issues = {"available": False, "disabled": True}, []
            return
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            self.conn_info = {"available": False,
                              "note": "Run DeviceWatch as administrator/root to inspect network connections."}
            self.conn_issues = []
            return
        names = {}

        def pname(pid):
            if not pid:
                return "unknown"
            if pid not in names:
                try:
                    names[pid] = psutil.Process(pid).name()
                except psutil.Error:
                    names[pid] = "unknown"
            return names[pid]

        def is_public(ip):
            try:
                return ipaddress.ip_address(ip.split("%")[0]).is_global
            except ValueError:
                return False

        ignore = {n.lower() for n in c["ignore_process_names"]}
        bad_ips = self.load_bad_ips()
        sus_ports = {int(p) for p in c.get("suspicious_remote_ports", []) if str(p).isdigit()}
        listeners, seen_l, established = [], set(), Counter()
        for cn in conns:
            if cn.status == psutil.CONN_LISTEN and cn.laddr and cn.type == socket.SOCK_STREAM:
                name = pname(cn.pid)
                exposed = cn.laddr.ip not in ("127.0.0.1", "::1")
                k = (name, cn.laddr.port, exposed)
                if k not in seen_l:
                    seen_l.add(k)
                    listeners.append({"process": name, "pid": cn.pid, "port": cn.laddr.port,
                                      "address": cn.laddr.ip, "exposed": exposed})
            elif cn.status == psutil.CONN_ESTABLISHED and cn.pid:
                established[cn.pid] += 1
        issues_new = {}
        if c.get("scan_open_ports", True):
            with STATE_LOCK:
                st = load_state()
                now_keys = {f"{l['process']}|{l['port']}" for l in listeners if l["exposed"]}
                base = st.get("listeners")
                if base is not None:
                    for k in sorted(now_keys - set(base)):
                        proc, port = k.rsplit("|", 1)
                        issues_new["net:port:" + k] = {
                            "severity": "warning", "key": "net:port:" + k,
                            "message": f"New program accepting incoming connections: {proc} on port {port}.",
                            "fix": "If you don't recognise it, block it in your firewall, end the process and run a full scan."}
                st["listeners"] = sorted(set(base or []) | now_keys)
                save_state(st)
        suspicious = 0
        if c.get("watch_outbound", True):
            for cn in conns:
                if cn.status != psutil.CONN_ESTABLISHED or not cn.raddr:
                    continue
                ip, port = cn.raddr.ip, cn.raddr.port
                if not is_public(ip):
                    continue
                if ip in bad_ips:
                    sev, why = "critical", f"connected to the known-bad address {ip}"
                elif port in sus_ports:
                    sev, why = "warning", f"connected to {ip}:{port}, a port often used by crypto-miners and backdoors"
                else:
                    continue
                name = pname(cn.pid)
                if name.lower() in ignore:
                    continue
                key = f"net:out:{name.lower()}:{ip}"
                suspicious += 1
                issues_new[key] = {"severity": sev, "key": key,
                                   "message": f"'{name}' {why}.",
                                   "fix": "Identify the program; if unfamiliar, end it, block the address in your firewall and run a full scan."}
        for key, issue in issues_new.items():
            self.sticky[key] = (time.time() + 86400, issue)
        top = [{"pid": pid, "name": pname(pid), "connections": n} for pid, n in established.most_common(5)]
        self.conn_info = {"available": True, "listeners": sorted(listeners, key=lambda l: (not l["exposed"], l["port"]))[:100],
                          "top": top, "established": sum(established.values()), "suspicious": suspicious,
                          "checked": datetime.now().isoformat(timespec="seconds")}
        self.conn_issues = []

    def integrity_scan(self):
        paths = self.cfg.get("integrity_paths") or []
        if not paths:
            self.integrity_info, self.integrity_issues, self.integrity_current = {"enabled": False}, [], {}
            return
        limit, current, count, limited = int(self.cfg.get("integrity_max_files", 2000)), {}, 0, False
        for raw in paths:
            p = Path(os.path.expandvars(str(raw))).expanduser()
            files = [p] if p.is_file() else p.rglob("*") if p.is_dir() else []
            for f in files:
                try:
                    if not f.is_file() or f.is_symlink() or f.stat().st_size > 50 * 1024 * 1024:
                        continue
                    if count >= limit:
                        limited = True
                        break
                    digest = self.hash_of(str(f))
                    if digest:
                        current[str(f)] = digest
                        count += 1
                except OSError:
                    continue
        self.integrity_current = current
        sig = hashlib.sha256("|".join(sorted(map(str, paths))).encode()).hexdigest()
        with STATE_LOCK:
            st = load_state()
            if st.get("integrity_sig") != sig or "integrity" not in st:
                st["integrity"], st["integrity_sig"] = current, sig
                save_state(st)
            base = st["integrity"]
        changed = sorted(p for p in current if p in base and base[p] != current[p])
        added = sorted(set(current) - set(base))
        removed = sorted(set(base) - set(current))
        issues = []
        if changed or added or removed:
            sample = ", ".join(Path(x).name for x in (changed + added + removed)[:3])
            issues.append({"severity": "warning", "key": "integrity:changed",
                           "message": f"Watched files changed: {len(changed)} modified, {len(added)} new, "
                                      f"{len(removed)} removed ({sample}...).",
                           "fix": "If you made these changes, click 'Accept changes' on the Security tab. "
                                  "If not, investigate: unexpected edits can mean malware or ransomware."})
        self.integrity_info = {"enabled": True, "files": len(current), "modified": changed[:20],
                               "new": added[:20], "removed": removed[:20], "limited": limited,
                               "checked": datetime.now().isoformat(timespec="seconds")}
        self.integrity_issues = issues

    def integrity_accept(self):
        with STATE_LOCK:
            st = load_state()
            st["integrity"] = dict(self.integrity_current)
            save_state(st)
        self.integrity_scan()

    def canary_scan(self):
        if not self.cfg.get("canary_enabled", True):
            self.canary_info, self.canary_issues = {"enabled": False}, []
            return
        dirs = [d for d in (Path.home() / "Documents", Path.home() / "Desktop") if d.is_dir()]
        want = hashlib.sha256(CANARY_TEXT.encode()).hexdigest()
        files, issues = [], []
        with STATE_LOCK:
            st = load_state()
            planted = st.setdefault("canaries", {})
            for d in dirs:
                f = d / CANARY_NAME
                if str(f) not in planted:
                    try:
                        f.write_text(CANARY_TEXT)
                        planted[str(f)] = want
                        logging.info("Planted ransomware canary file: %s", f)
                    except OSError:
                        continue
                ok = False
                try:
                    ok = hashlib.sha256(f.read_bytes()).hexdigest() == planted[str(f)]
                except OSError:
                    pass
                files.append({"path": str(f), "ok": ok})
                if not ok:
                    issues.append({"severity": "critical", "key": "canary:" + str(f),
                                   "message": f"Ransomware canary file was modified, renamed or deleted: {f}",
                                   "fix": "Disconnect from the network NOW if you did not touch it, find the process "
                                          "changing your files (Processes tab) and end it. Restore from backup if needed. "
                                          "Then use 'Reset canaries' in Settings."})
            save_state(st)
        self.canary_info = {"enabled": True, "files": files,
                            "checked": datetime.now().isoformat(timespec="seconds")}
        self.canary_issues = issues

    def canary_reset(self):
        with STATE_LOCK:
            st = load_state()
            for p in list(st.get("canaries", {})):
                try:
                    Path(p).unlink()
                except OSError:
                    pass
            st["canaries"] = {}
            save_state(st)
        self.canary_scan()

    def usb_scan(self):
        if not self.cfg.get("usb_alerts", True):
            self.usb_current = []
            return
        current = usb_devices()
        if self.usb_known is not None:
            for dev in sorted(current - self.usb_known):
                key = "usb:" + dev[:100]
                self.sticky[key] = (time.time() + 3600, {
                    "severity": "notice", "key": key,
                    "message": f"New USB device connected: {dev}",
                    "fix": "If you didn't plug in anything, unplug it. Unknown USB devices can carry malware or act as keyboards."})
        self.usb_known, self.usb_current = current, sorted(current)

    def login_scan(self):
        count = failed_logins_last_hour()
        self.login_count = count
        warn = self.cfg.get("failed_logins_per_hour_warn", 5)
        self.login_issues = []
        if count is not None and count >= warn:
            self.login_issues.append({
                "severity": "warning", "key": "logins:failed",
                "message": f"{count} failed sign-in attempts in the last hour.",
                "fix": "If it wasn't you, change your password, enable 2FA, and make sure remote access (RDP/SSH) isn't exposed to the internet."})

    def boot_scan(self):
        if not self.cfg.get("boot_analysis_enabled", True):
            return
        info = boot_analysis()
        self.boot_info = info
        self.boot_issues = []
        slow = self.cfg.get("boot_slow_seconds", 120)
        if info.get("boot_seconds") and info["boot_seconds"] >= slow:
            self.boot_issues.append({
                "severity": "notice", "key": "boot:slow",
                "message": f"The last boot took {info['boot_seconds']} seconds.",
                "fix": "Disable startup programs you don't need (Task Manager > Startup, or the list on the Hardware tab)."})

    def leak_scan(self):
        c = self.cfg
        if not c.get("leak_check_enabled", True):
            self.leak_issues = []
            return
        now, window = time.time(), c["leak_window_minutes"] * 60
        seen = set()
        for p in psutil.process_iter(["pid", "name", "memory_info", "create_time"]):
            try:
                rss = p.info["memory_info"].rss
                key = (p.info["pid"], p.info["create_time"])
            except (AttributeError, KeyError, TypeError):
                continue
            if rss < 150 * 1048576:
                continue
            seen.add(key)
            h = self.leak_hist.setdefault(key, {"name": p.info["name"], "pts": deque()})
            h["pts"].append((now, rss))
            while h["pts"] and now - h["pts"][0][0] > window * 1.5:
                h["pts"].popleft()
        for key in list(self.leak_hist):
            if key not in seen:
                del self.leak_hist[key]
        issues = []
        for key, h in self.leak_hist.items():
            pts = list(h["pts"])
            if len(pts) < 6 or pts[-1][0] - pts[0][0] < window * 0.9:
                continue
            growth = (pts[-1][1] - pts[0][1]) / 1048576
            steps = [b[1] - a[1] for a, b in zip(pts, pts[1:])]
            rising = sum(1 for s in steps if s >= 0) / len(steps)
            if growth >= c["leak_growth_mb"] and rising >= 0.8:
                issues.append({"severity": "notice", "key": f"leak:{h['name'].lower()}",
                               "message": f"'{h['name']}' (PID {key[0]}) keeps growing: +{growth:.0f} MB in the last "
                                          f"{(pts[-1][0] - pts[0][0]) / 60:.0f} minutes (now {pts[-1][1] / 1048576:.0f} MB).",
                               "fix": "This looks like a memory leak. Restart that program; update it if the problem repeats."})
        self.leak_issues = issues

    def service_watch(self):
        names = [str(n).strip() for n in (self.cfg.get("watch_services") or [])]
        info, issues, now = [], [], time.time()
        for name in names:
            if not SERVICE_RE.match(name):
                continue
            state = service_state(name)
            info.append({"name": name, "state": state})
            if state != "stopped":
                continue
            recent = [t for t in self.svc_restarts.get(name, []) if now - t < 3600]
            if len(recent) < self.cfg.get("service_restart_max_per_hour", 3):
                ok = restart_service(name)
                recent.append(now)
                logging.warning("Service '%s' was stopped; restart %s", name, "succeeded" if ok else "FAILED")
                issues.append({"severity": "notice" if ok else "warning", "key": f"svc:{name}",
                               "message": f"Service '{name}' had stopped; automatic restart {'succeeded' if ok else 'failed'}.",
                               "fix": "Check the service's logs if it keeps stopping." if ok else
                                      "Start it manually (may need administrator rights) and check its logs."})
            else:
                issues.append({"severity": "warning", "key": f"svc:{name}",
                               "message": f"Service '{name}' keeps stopping (restart limit reached).",
                               "fix": "Look at the service's logs; automatic restarts are paused until the hour is up."})
            self.svc_restarts[name] = recent
        self.svc_info, self.svc_issues = info, issues

    def speed_scan(self, force=False):
        c = self.cfg
        if not (force or c.get("speedtest_enabled", True)):
            return
        res = speed_test(c)
        self.speed_hist.append(res)
        try:
            with open(SPEED_PATH, "a") as f:
                f.write(json.dumps(res) + "\n")
        except OSError:
            pass
        self.speed_issues = []
        dl = res.get("download_mbps")
        if dl is not None and dl < c.get("speedtest_warn_mbps", 5):
            self.speed_issues.append({
                "severity": "notice", "key": "speedtest:slow",
                "message": f"Internet download speed is low ({dl} Mbps).",
                "fix": "Restart your router, move closer to it or use a cable, and check whether other devices are using the connection."})

    # --------------------------------------------------------------- updates
    def update_scan(self):
        if not self.cfg["check_updates"]:
            return
        info = check_updates()
        issues = []
        top = ", ".join(info["titles"][:3]) + ("..." if info["count"] > 3 else "")
        how = {"Windows": "Settings > Windows Update > Install now.",
               "Darwin": "System Settings > General > Software Update.",
               "Linux": "Run: sudo apt update && sudo apt upgrade (or your distro's equivalent)."}.get(OS, "Install updates.")
        if info["security"]:
            issues.append({"severity": "warning", "key": "update:security",
                           "message": f"{info['security']} security update(s) waiting to be installed ({info['count']} total): {top}",
                           "fix": "Install them soon - security patches close holes attackers actively exploit. " + how})
        elif info["count"]:
            issues.append({"severity": "notice", "key": "update:other",
                           "message": f"{info['count']} update(s) available: {top}", "fix": how})
        if info["reboot"]:
            issues.append({"severity": "notice", "key": "reboot",
                           "message": "A restart is pending to finish installing updates.",
                           "fix": "Save your work and restart your device."})
        self.update_info, self.update_issues = info, issues

    def disk_health_scan(self):
        if not self.cfg.get("check_disk_health", True):
            self.disk_info, self.disk_issues = {"available": False, "devices": [], "disabled": True}, []
            return
        info = disk_health_status()
        issues = []
        for device in info["devices"]:
            if device.get("healthy") is False:
                detail = "; ".join(device.get("problems", []))
                issues.append({"severity": "warning", "key": "diskhealth:" + device["name"],
                               "message": f"Disk health warning for {device['name']}: {device['status']}"
                                          + (f" ({detail})" if detail else "."),
                               "fix": "Back up important files now and review the drive with its vendor diagnostics."})
        self.disk_info, self.disk_issues = info, issues

    def app_update_scan(self):
        if not self.cfg.get("check_app_updates", True):
            self.app_info, self.app_issues = {"available": False, "apps": [], "disabled": True}, []
            return
        info = app_update_status()
        issues = []
        if info["count"]:
            names = ", ".join(app.get("name", "unknown app") for app in info["apps"][:5])
            issues.append({"severity": "notice", "key": "app_updates",
                           "message": f"{info['count']} application update(s) available: {names}",
                           "fix": "Review and install updates with your package manager (winget, Homebrew, Flatpak, or Snap)."})
        self.app_info, self.app_issues = info, issues

    def backup_scan(self):
        info = backup_status(self.cfg.get("backup_paths", []), self.cfg.get("backup_max_age_days", 7))
        issues = []
        for backup in info:
            if not backup["fresh"]:
                reason = "not found" if backup["age_days"] is None else f"last changed {backup['age_days']} days ago"
                issues.append({"severity": "warning", "key": "backup:" + backup["path"],
                               "message": f"Backup target {backup['path']} is {reason}.",
                               "fix": "Run a backup and confirm that the configured path points to the backup artifact or folder."})
        self.backup_info, self.backup_issues = info, issues

    def run_all_scans_once(self):
        for fn in (self.security_scan, self.update_scan, self.disk_health_scan, self.app_update_scan,
                   self.backup_scan, self.connection_scan, self.integrity_scan, self.canary_scan,
                   self.usb_scan, self.login_scan, self.boot_scan, self.service_watch, self.speed_scan):
            try:
                fn()
            except Exception:
                logging.exception("%s failed", fn.__name__)

    def start_background(self):
        c = self.cfg

        def loop(fn, every):
            while True:
                try:
                    fn()
                except Exception:
                    logging.exception("%s failed", fn.__name__)
                time.sleep(every)
        jobs = [(self.security_scan, c["scan_interval_minutes"] * 60),
                (self.update_scan, c["update_check_hours"] * 3600),
                (self.disk_health_scan, c.get("disk_health_check_hours", 6) * 3600),
                (self.app_update_scan, c.get("app_check_hours", 12) * 3600),
                (self.backup_scan, c.get("backup_check_hours", 1) * 3600),
                (self.connection_scan, c.get("connection_scan_seconds", 120)),
                (self.integrity_scan, c.get("integrity_check_minutes", 30) * 60),
                (self.canary_scan, 60),
                (self.usb_scan, 30),
                (self.login_scan, 3600),
                (self.boot_scan, 86400),
                (self.leak_scan, 300),
                (self.service_watch, 60),
                (self.speed_scan, c.get("speedtest_hours", 6) * 3600)]
        for fn, every in jobs:
            threading.Thread(target=loop, args=(fn, max(10, every)), daemon=True).start()

    # --------------------------------------------------------------- actions
    def auto_fix_disk(self):
        """Delete temp files older than 7 days. Only touches the OS temp directory."""
        cutoff, freed = time.time() - 7 * 86400, 0
        for f in Path(tempfile.gettempdir()).rglob("*"):
            try:
                if f.is_file() and not f.is_symlink() and f.stat().st_mtime < cutoff:
                    size = f.stat().st_size
                    f.unlink()
                    freed += size
            except Exception:
                continue
        logging.info("Auto-fix: freed %.1f MB of old temp files", freed / 1024 ** 2)
        return round(freed / 1024 ** 2, 1)

    def run_fix(self, name):
        if name == "temp":
            return f"Freed {self.auto_fix_disk()} MB of old temp files."
        if name == "browser_cache":
            freed = delete_files_in(browser_cache_dirs())
            logging.info("Auto-fix: cleared browser caches (%.1f MB)", freed / 1024 ** 2)
            return f"Cleared browser caches ({round(freed / 1024 ** 2, 1)} MB). Cookies and passwords were not touched."
        if name == "recycle_bin":
            return empty_recycle_bin()
        if name == "dns":
            return flush_dns()
        return "Unknown fix."

    def notify_desktop(self, title, msg):
        title, msg = title.replace('"', "'").replace("`", "'"), msg.replace('"', "'").replace("`", "'")
        try:
            if OS == "Windows":
                script = ("[void][reflection.assembly]::LoadWithPartialName('System.Windows.Forms');"
                          "$n=New-Object System.Windows.Forms.NotifyIcon;"
                          "$n.Icon=[System.Drawing.SystemIcons]::Warning;$n.Visible=$true;"
                          f"$n.ShowBalloonTip(8000,'{title.replace(chr(39), '')}','{msg.replace(chr(39), '')}',[System.Windows.Forms.ToolTipIcon]::Warning);"
                          "Start-Sleep 9;$n.Dispose()")
                subprocess.Popen(["powershell", "-NoProfile", "-Command", script],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 creationflags=CREATE_NO_WINDOW)
            elif OS == "Darwin":
                subprocess.Popen(["osascript", "-e", f'display notification "{msg}" with title "{title}"'])
            else:
                subprocess.Popen(["notify-send", title, msg])
        except Exception as e:
            logging.warning("Desktop notification failed: %s", e)

    def send_email(self, subject, body):
        e = self.cfg["email"]
        if not (e["enabled"] and e["to"]):
            return
        try:
            mail = EmailMessage()
            mail["Subject"], mail["From"], mail["To"] = subject, e["username"], e["to"]
            mail.set_content(body)
            with smtplib.SMTP(e["smtp_host"], e["smtp_port"], timeout=15) as s:
                s.starttls()
                s.login(e["username"], e["password"])
                s.send_message(mail)
        except Exception as ex:
            logging.warning("Email failed: %s", ex)

    def send_webhook(self, text):
        url = self.cfg["webhook_url"]
        if not url:
            return
        try:
            req = urllib.request.Request(url, json.dumps({"text": text, "content": text}).encode(),
                                         {"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10).close()
        except Exception as ex:
            logging.warning("Webhook failed: %s", type(ex).__name__)

    def send_telegram(self, text):
        token, chat = self.cfg.get("telegram_bot_token"), self.cfg.get("telegram_chat_id")
        if not (token and chat):
            return
        try:
            req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage",
                                         json.dumps({"chat_id": chat, "text": text[:4000]}).encode(),
                                         {"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10).close()
        except Exception as ex:
            logging.warning("Telegram failed: %s", type(ex).__name__)   # never log the URL (it contains the token)

    def broadcast(self, subject, text, desktop=False):
        if desktop:
            self.notify_desktop(subject, text.replace("\n", " ")[:240])
        self.send_email(subject, text)
        self.send_webhook(text)
        self.send_telegram(text)

    def dispatch(self, issues):
        c = self.cfg
        base = c["alert_cooldown_minutes"] * 60
        esc_s = max(60, int(c.get("escalation_minutes", 10)) * 60)
        long_keys = ("mal:startup", "mal:hosts", "update", "reboot", "app_updates", "backup:", "net:port",
                     "net:out", "integrity:", "usb:", "leak:", "boot:", "speedtest", "diskhealth:")
        fresh = []
        for i in issues:
            if i["severity"] == "info":
                continue
            is_long = i["key"].startswith(long_keys)
            cooldown = 86400 if is_long else base
            if i["severity"] == "critical" and c.get("escalate_critical", True) and not is_long:
                cooldown = min(cooldown, esc_s)          # keep nagging until it is fixed
            if time.time() - self.last_alert.get(i["key"], 0) >= cooldown:
                self.last_alert[i["key"]] = time.time()
                fresh.append(i)
        if not fresh:
            return
        host = c.get("device_name") or platform.node()
        text = "\n".join(f"[{i['severity'].upper()}] {i['message']}\n  -> {i['fix']}" for i in fresh)
        logging.warning("Alerts on %s:\n%s", host, text)
        popup = fresh
        if in_quiet_hours(c):
            popup = [i for i in fresh if i["severity"] == "critical"]   # quiet hours: only critical popups
        if c["desktop_notifications"] and popup:
            self.notify_desktop(f"DeviceWatch: {len(popup)} issue(s)", "; ".join(i["message"] for i in popup)[:240])
        self.send_email(f"[DeviceWatch] {len(fresh)} issue(s) on {host}", text)
        self.send_webhook(f"DeviceWatch on {host}:\n{text}")
        self.send_telegram(f"DeviceWatch on {host}:\n{text}")
        if c["auto_fix"]:
            keys = [i["key"] for i in fresh]
            actions = c.get("auto_fix_actions") or []
            if any(k.startswith("disk:") and k != "disk:io" for k in keys):
                for a in ("temp", "browser_cache", "recycle_bin"):
                    if a in actions:
                        logging.info("Auto-fix: %s", self.run_fix(a))
            if "network" in keys or "network:quality" in keys:
                if "dns" in actions:
                    logging.info("Auto-fix: %s", self.run_fix("dns"))

    # --------------------------------------------------------------- summary
    def build_summary(self, hours):
        c = self.cfg
        host = c.get("device_name") or platform.node()
        rows = read_history(hours)
        if not rows:
            return f"DeviceWatch summary for {host}: no data collected yet."
        scores = [r["score"] for r in rows if r.get("score") is not None]
        cpus = [r["cpu"] for r in rows if r.get("cpu") is not None]
        rams = [r["ram"] for r in rows if r.get("ram") is not None]
        worst = min(rows, key=lambda r: r.get("score", 100))
        counts = Counter(k for r in rows for k in r.get("issues", []))
        mins = c["interval_seconds"] / 60
        lines = [f"DeviceWatch {'weekly' if hours > 24 else 'daily'} summary - {host}",
                 f"Period: last {hours} h ({len(rows)} checks)",
                 f"Health score: average {round(sum(scores) / len(scores))}, lowest {min(scores)} at {worst['t']}",
                 f"CPU: average {round(sum(cpus) / len(cpus))}%, peak {max(cpus):.0f}%" if cpus else "",
                 f"RAM: average {round(sum(rams) / len(rams))}%, peak {max(rams):.0f}%" if rams else ""]
        if counts:
            lines.append("Most frequent issues:")
            lines += [f"  - {k}: about {max(1, round(n * mins))} min" for k, n in counts.most_common(5)]
        else:
            lines.append("No issues were recorded.")
        up = self.update_info or {}
        if up.get("checked"):
            lines.append(f"Pending updates: {up.get('count', 0)} ({up.get('security', 0)} security)")
        return "\n".join(l for l in lines if l)

    def maybe_summary(self):
        c = self.cfg
        if not c.get("summary_enabled"):
            return
        now = datetime.now()
        if now.hour < int(c.get("summary_hour", 8)):
            return
        weekly = c.get("summary_frequency") == "weekly"
        with STATE_LOCK:
            st = load_state()
            try:
                last = datetime.fromisoformat(st["last_summary"]) if st.get("last_summary") else None
            except ValueError:
                last = None
            due = (last is None or last.date() != now.date()) and (not weekly or now.weekday() == 0)
            if not due:
                return
            st["last_summary"] = now.isoformat(timespec="seconds")
            save_state(st)
        text = self.build_summary(168 if weekly else 24)
        logging.info("Sending %s summary", "weekly" if weekly else "daily")
        self.broadcast(f"[DeviceWatch] {'Weekly' if weekly else 'Daily'} summary", text)

    # ------------------------------------------------------- multi-device hub
    def status_summary(self):
        res = self.latest
        m = res.get("metrics", {})
        return {"name": self.cfg.get("device_name") or platform.node(), "os": m.get("os", ""),
                "score": res.get("score"), "cpu": m.get("cpu_percent"), "ram": m.get("ram_percent"),
                "disk": max((d["percent"] for d in m.get("disks", [])), default=None),
                "battery": m.get("battery_percent"), "time": m.get("time"),
                "issues": [{"severity": i["severity"], "message": i["message"]} for i in res.get("issues", [])][:20]}

    def push_to_hub(self):
        url, token = self.cfg.get("hub_url", "").rstrip("/"), self.cfg.get("hub_token", "")
        if not (url and token):
            return
        try:
            req = urllib.request.Request(url + "/api/push", json.dumps(self.status_summary()).encode(),
                                         {"Content-Type": "application/json", "X-Hub-Token": token})
            urllib.request.urlopen(req, timeout=8).close()
        except Exception as ex:
            logging.warning("Could not reach the hub: %s", type(ex).__name__)

    def hub_issues(self):
        if not self.cfg.get("hub_enabled"):
            return []
        now, out = time.time(), []
        for name, d in list(self.devices.items()):
            if now - d["received"] > 300:
                out.append({"severity": "notice", "key": "hub:offline:" + name,
                            "message": f"Device '{name}' has not reported for {int((now - d['received']) / 60)} min.",
                            "fix": "Check that it is on, online and that DeviceWatch is running on it."})
        return out

    def devices_view(self):
        if not self.cfg.get("hub_enabled"):
            return {"enabled": False, "devices": []}
        now = time.time()
        me = self.status_summary()
        me.update(age=0, online=True, this_device=True)
        others = []
        for d in self.devices.values():
            row = {k: v for k, v in d.items() if k != "received"}
            row.update(age=int(now - d["received"]), online=now - d["received"] <= 300, this_device=False)
            others.append(row)
        return {"enabled": True, "token_set": bool(self.cfg.get("hub_token")),
                "devices": [me] + sorted(others, key=lambda r: r["name"])}

    def tick(self):
        self.latest = self.collect()
        m = self.latest["metrics"]
        row = {"t": m["time"], "score": self.latest["score"], "cpu": m["cpu_percent"],
               "ram": m["ram_percent"], "battery": m.get("battery_percent"),
               "battery_health": m.get("battery_health_percent"),
               "network_latency": m.get("network_latency_ms"), "temperature": m.get("max_temp_c"),
               "wifi": m.get("wifi_signal_percent"),
               "gpu": m["gpus"][0]["util"] if m.get("gpus") else None,
               "tc": [[p["name"], p["cpu"]] for p in m["top_cpu"][:3]],
               "tm": [[p["name"], p["mem"]] for p in m["top_mem"][:3]],
               "issues": [i["key"] for i in self.latest["issues"]]}
        try:
            with open(HISTORY_PATH, "a") as f:
                f.write(json.dumps(row) + "\n")
        except OSError:
            pass
        self.dispatch(self.latest["issues"])
        try:
            self.maybe_summary()
        except Exception:
            logging.exception("Summary failed")
        if self.cfg.get("hub_url") and self.cfg.get("hub_token"):
            threading.Thread(target=self.push_to_hub, daemon=True).start()
        return self.latest


# --------------------------------------------------------------------- report
def build_report_html(mon):
    e = html.escape
    res = mon.latest
    m = res.get("metrics", {})

    def row(a, b):
        return f"<tr><th>{e(str(a))}</th><td>{e(str(b))}</td></tr>"
    rows = [row("Computer", f"{m.get('host')} ({m.get('os')})"), row("Generated", m.get("time")),
            row("Health score", f"{res.get('score')}/100"),
            row("CPU", f"{m.get('cpu_percent')}%  ({m.get('cpu_cores')} cores)"),
            row("Memory", f"{m.get('ram_percent')}%  ({m.get('ram_used_gb')} / {m.get('ram_total_gb')} GB)"),
            row("Uptime", f"{m.get('uptime_days')} days")]
    rows += [row(f"Disk {d['mount']}", f"{d['percent']}% used, {d['free_gb']} GB free") for d in m.get("disks", [])]
    if m.get("battery_percent") is not None:
        rows.append(row("Battery", f"{m['battery_percent']}% ({'charging' if m.get('battery_plugged') else 'on battery'})"))
    if m.get("battery_health_percent") is not None:
        rows.append(row("Battery health", f"{m['battery_health_percent']}% ({m.get('battery_health_label', '')})"))
    rows.append(row("Network", f"{'online' if m.get('network_ok') else 'OFFLINE'}, {m.get('network_latency_ms')} ms, "
                               f"{m.get('network_loss_percent')}% probe loss"))
    if m.get("wifi_signal_percent") is not None:
        rows.append(row("Wi-Fi signal", f"{m['wifi_signal_percent']}% ({m.get('wifi_ssid', '')})"))
    for st in m.get("speedtests", [])[-1:]:
        rows.append(row("Last speed test", f"{st.get('download_mbps', 'n/a')} Mbps down / {st.get('upload_mbps', 'n/a')} Mbps up ({st.get('time')})"))
    for g in m.get("gpus", []):
        rows.append(row(f"GPU {g['name']}", f"{g['util']}% load, {g['temp']} C"))
    for d in (m.get("disk_health") or {}).get("devices", []):
        rows.append(row(f"Drive {d['name']}", d["status"]))
    for b in m.get("backups", []):
        rows.append(row(f"Backup {b['path']}", "not found" if b["age_days"] is None else f"{b['age_days']} days old"))
    sec = m.get("security") or {}
    if sec.get("summary"):
        rows.append(row("Security", sec["summary"]))
    up = m.get("updates") or {}
    if up.get("checked"):
        rows.append(row("OS updates", f"{up['count']} pending ({up['security']} security)"))
    boot = m.get("boot") or {}
    if boot.get("boot_seconds"):
        rows.append(row("Last boot time", f"{boot['boot_seconds']} seconds"))
    issues = "".join(f"<li class='{e(i['severity'])}'><b>[{e(i['severity'].upper())}]</b> {e(i['message'])}"
                     f"<br><small>Fix: {e(i['fix'])}</small></li>" for i in res.get("issues", [])) \
        or "<li>No problems detected.</li>"
    procs = "".join(f"<li>{e(p['name'])}: CPU {p['cpu']}%</li>" for p in m.get("top_cpu", [])[:5])
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>DeviceWatch report</title><style>
body{{font:14px system-ui,sans-serif;max-width:860px;margin:24px auto;padding:0 16px;color:#1b1f24}}
h1{{font-size:22px}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid #e5e7eb}}
th{{width:30%;color:#6b7280;font-weight:600}}li{{margin:8px 0}}li.critical{{color:#b91c1c}}li.warning{{color:#b45309}}
button{{padding:8px 14px;border:0;border-radius:8px;background:#2563eb;color:#fff;cursor:pointer}}@media print{{button{{display:none}}}}
</style></head><body><h1>DeviceWatch health report</h1>
<p><button onclick="window.print()">Print / Save as PDF</button></p>
<table>{''.join(rows)}</table><h2>Issues</h2><ul>{issues}</ul><h2>Top CPU processes</h2><ul>{procs}</ul></body></html>"""


# ------------------------------------------------------------------ dashboard
PAGE = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DeviceWatch</title><style>
:root{--bg:#f4f5f7;--card:#fff;--tx:#1b1f24;--mut:#6b7280;--ok:#16a34a;--warn:#d97706;--bad:#dc2626;--acc:#2563eb;--bd:#e5e7eb}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0f1115;--card:#181b21;--tx:#e6e8eb;--mut:#9aa3af;--bd:#262a32;--acc:#60a5fa}}
:root[data-theme=dark]{--bg:#0f1115;--card:#181b21;--tx:#e6e8eb;--mut:#9aa3af;--bd:#262a32;--acc:#60a5fa}
*{box-sizing:border-box}body{margin:0;font:14px system-ui,sans-serif;background:var(--bg);color:var(--tx)}
header{display:flex;align-items:center;gap:14px;padding:14px 20px;background:var(--card);border-bottom:1px solid var(--bd);flex-wrap:wrap}
header h1{font-size:17px;margin:0}.mut{color:var(--mut);font-size:12px}.sp{margin-left:auto;display:flex;gap:8px}
nav{display:flex;gap:4px;padding:8px 20px;overflow-x:auto;background:var(--card);border-bottom:1px solid var(--bd)}
nav button{border:0;background:none;color:var(--mut);padding:8px 14px;border-radius:8px;cursor:pointer;font:inherit;white-space:nowrap}
nav button.on{background:var(--acc);color:#fff}main{max-width:1000px;margin:auto;padding:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-bottom:14px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px;margin-bottom:12px;overflow-x:auto}.grid .card{margin:0}
.big{font-size:26px;font-weight:650;margin:2px 0}.bar{height:6px;background:var(--bd);border-radius:4px;margin-top:8px;overflow:hidden}.bar i{display:block;height:100%}
.issue{border-left:4px solid var(--warn);padding:8px 12px;margin:8px 0;background:var(--bg);border-radius:6px;display:flex;gap:10px;justify-content:space-between;align-items:center}
.issue.critical{border-color:var(--bad)}.issue.notice,.issue.info{border-color:var(--acc)}.ok{color:var(--ok)}.bad{color:var(--bad)}.warnc{color:var(--warn)}
button.a,a.a{background:var(--acc);color:#fff;border:0;padding:7px 13px;border-radius:8px;cursor:pointer;font:inherit;text-decoration:none;display:inline-block}
.a.s{background:var(--bd);color:var(--tx)}.a.d{background:var(--bad)}
table{width:100%;border-collapse:collapse}td,th{padding:6px 4px;text-align:left;border-bottom:1px solid var(--bd);vertical-align:top}
input:not([type=checkbox]){width:100%;padding:7px;border:1px solid var(--bd);border-radius:8px;background:var(--bg);color:var(--tx)}
label{display:block;margin:8px 0;text-transform:capitalize;font-size:12px;color:var(--mut)}label input[type=checkbox]{margin-left:8px}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}pre{white-space:pre-wrap;font-size:12px;max-height:340px;overflow:auto;margin:0}
#toast{position:fixed;bottom:18px;right:18px;background:var(--tx);color:var(--bg);padding:10px 16px;border-radius:8px;display:none;z-index:9}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}
@media(max-width:600px){main{padding:10px}header{padding:10px 12px}nav{padding:6px 10px}.big{font-size:22px}.cols{grid-template-columns:1fr}.issue{flex-direction:column;align-items:flex-start}.sp{margin-left:0}}
</style></head><body>
<header><svg width=54 height=54 viewBox="0 0 100 100"><circle cx=50 cy=50 r=42 fill=none stroke="var(--bd)" stroke-width=10 /><circle id=ring cx=50 cy=50 r=42 fill=none stroke="var(--ok)" stroke-width=10 stroke-linecap=round transform="rotate(-90 50 50)" stroke-dasharray="0 264"/><text id=sc x=50 y=58 text-anchor=middle font-size=26 font-weight=700 fill="currentColor">-</text></svg>
<div><h1 id=host>DeviceWatch</h1><div class=mut id=sub>loading...</div></div>
<div class=sp><a class="a s" href="/report" target="_blank">Report</a><button class="a s" onclick="theme()">Light/Dark</button></div></header>
<nav id=nav></nav><main id=main></main><div id=toast></div>
<script>
const TOKEN="__TOKEN__",TABS=['Overview','Hardware','Network','Security','Updates','Processes','History','Devices','Alerts','Settings'];
let tab='Overview',S={},H=[],SP=[],DEV={},CFG={},LOG='',RANGE='1h',editing=false;
try{const t=localStorage.getItem('dw-theme');if(t)document.documentElement.dataset.theme=t}catch(e){}
const $=id=>document.getElementById(id),col=(v,inv)=>{v=inv?100-v:v;return v>=90?'var(--bad)':v>=75?'var(--warn)':'var(--ok)'};
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function toast(t){const e=$('toast');e.textContent=t;e.style.display='block';setTimeout(()=>e.style.display='none',4500)}
function theme(){const cur=document.documentElement.dataset.theme||(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light');const n=cur==='dark'?'light':'dark';document.documentElement.dataset.theme=n;try{localStorage.setItem('dw-theme',n)}catch(e){}}
async function api(p,body){const o=body?{method:'POST',headers:{'X-Token':TOKEN,'Content-Type':'application/json'},body:JSON.stringify(body)}:{};return (await fetch(p,o)).json()}
async function act(name,arg){const r=await api('/api/action',{name,arg});toast(r.msg||'Done');await load(true)}
const tile=(n,v,s,inv)=>`<div class=card><div class=mut>${n}</div><div class=big>${v==null?'...':v+'%'}</div><div class=mut>${s||''}</div><div class=bar><i style="width:${Math.min(100,v||0)}%;background:${col(v||0,inv)}"></i></div></div>`;
const spark=(a,c,auto,unit)=>{a=(a||[]).filter(v=>v!=null);if(a.length<2)return'<div class=mut>Collecting data...</div>';const lo=auto?Math.min(...a):0,hi=auto?Math.max(...a):100,sp=(hi-lo)||1;const p=a.map((v,i)=>`${(i*300/(a.length-1)).toFixed(1)},${(58-((v-lo)/sp)*56).toFixed(1)}`).join(' ');return`<svg viewBox="0 0 300 60" width=100% height=60 preserveAspectRatio=none><polyline fill=none stroke="${c}" stroke-width=2 vector-effect="non-scaling-stroke" points="${p}"/></svg><div class=mut>now ${a[a.length-1]}${unit||''} | max ${Math.max(...a)}${unit||''}</div>`};
const chart=(t,key,c,auto,unit)=>`<div class=card><b>${t}</b>${spark(H.map(x=>x[key]),c,auto,unit)}</div>`;
const rangeBar=()=>'<div class="row" style="margin-bottom:12px">'+['1h','24h','7d','30d'].map(r=>`<button class="a ${r===RANGE?'':'s'}" onclick="RANGE='${r}';load(true)">${r}</button>`).join('')+'</div>';
const issueHtml=x=>`<div class="issue ${esc(x.severity)}"><div><b>${esc(x.message)}</b><div class=mut>${esc(x.fix)}</div></div>${x.key.startsWith('mal:proc:')?`<button class="a s" data-n="${esc(x.key.slice(9))}" onclick="act('ignore',this.dataset.n)">Ignore</button>`:''}</div>`;
const ptable=(t,a,k,u)=>`<div class=card><b>${t}</b><table>${(a||[]).map(x=>`<tr><td>${esc(x.name)}</td><td>${esc(x[k])}${u}</td><td><button class="a d" data-pid="${esc(x.pid)}" data-n="${esc(x.name)}" onclick="if(confirm('End '+this.dataset.n+' (PID '+this.dataset.pid+')?'))act('kill',Number(this.dataset.pid))">End</button></td></tr>`).join('')||'<tr><td class=mut>No data</td></tr>'}</table></div>`;
const fields=(o,p='')=>Object.entries(o).map(([k,v])=>{const id=p+k;if(v&&typeof v==='object'&&!Array.isArray(v))return`<h4>${esc(k)}</h4>`+fields(v,id+'.');
const t=typeof v==='boolean'?`<input type=checkbox data-k="${esc(id)}" data-t=b ${v?'checked':''}>`:Array.isArray(v)?`<input data-k="${esc(id)}" data-t=a value="${esc(v.join(', '))}">`:`<input data-k="${esc(id)}" data-t=${typeof v==='number'?'n':'s'} value="${esc(v)}" ${/password|key|token|webhook/.test(id)?'type=password':''}>`;return`<label>${esc(k.replace(/_/g,' '))}${t}</label>`}).join('');
async function save(){const o={};document.querySelectorAll('[data-k]').forEach(e=>{let v=e.dataset.t==='b'?e.checked:e.dataset.t==='n'?Number(e.value):e.dataset.t==='a'?e.value.split(',').map(s=>s.trim()).filter(Boolean):e.value;let r=o,ks=e.dataset.k.split('.');ks.slice(0,-1).forEach(k=>r=r[k]=r[k]||{});r[ks.pop()]=v});const r=await api('/api/config',o);toast(r.msg);CFG=await api('/api/config')}
function view(){const m=S.metrics||{},sc=m.security||{},u=m.updates||{},is=S.issues||[],cn=m.connections||{};let h='';
if(tab==='Overview'){h+=rangeBar()+'<div class=grid>'+tile('CPU',m.cpu_percent,(m.cpu_cores||'?')+' cores')+tile('Memory',m.ram_percent,(m.ram_used_gb||0)+' / '+(m.ram_total_gb||0)+' GB');(m.disks||[]).forEach(d=>h+=tile('Disk '+esc(d.mount),d.percent,d.free_gb+' GB free'));
if(m.battery_percent!=null)h+=tile('Battery',m.battery_percent,m.battery_plugged?'charging':'on battery',true);if(m.battery_health_percent!=null)h+=tile('Battery health',m.battery_health_percent,esc(m.battery_health_label||'')+' | '+m.battery_wear_percent+'% wear'+(m.battery_cycle_count!=null?' | '+m.battery_cycle_count+' cycles':''),true);if(m.max_temp_c!=null)h+=tile('Temperature',m.max_temp_c,m.max_temp_c+' C');
(m.gpus||[]).forEach(g=>h+=tile('GPU '+esc(g.name),g.util,g.temp+' C | '+g.mem_used_mb+'/'+g.mem_total_mb+' MB'));
if(m.wifi_signal_percent!=null)h+=tile('Wi-Fi signal',m.wifi_signal_percent,esc(m.wifi_ssid||''),true);
h+=`<div class=card><div class=mut>Network</div><div class=big>${m.network_ok?'<span class=ok>Online</span>':'<span class=bad>Offline</span>'}</div><div class=mut>${m.network_latency_ms==null?'latency unavailable':m.network_latency_ms+' ms average'} | ${m.network_loss_percent||0}% probe loss</div><div class=mut>down ${m.net_down_mbps??'-'} / up ${m.net_up_mbps??'-'} Mbps | uptime ${m.uptime_days} d</div></div>`;
h+=`<div class=card><div class=mut>Protection</div><div class=big>${sc.av_ok===false?'<span class=bad>At risk</span>':sc.last_scan?'<span class=ok>OK</span>':'...'}</div><div class=mut>${esc(sc.summary||'scanning...')}</div></div>`;
h+=`<div class=card><div class=mut>Updates</div><div class=big>${u.checked?u.count:'...'}</div><div class=mut>${u.checked?u.security+' security':'checking...'}</div></div></div>`;
h+=`<div class=cols>${chart('CPU history','cpu','var(--acc)')}${chart('Memory history','ram','var(--warn)')}${chart('Health score','score','var(--ok)')}</div>`;
h+='<div class=card><b>Current issues</b>'+(is.length?is.map(issueHtml).join(''):'<div class=ok>No problems detected.</div>')+'</div>'}
if(tab==='Hardware'){const dh=m.disk_health||{},bs=m.backups||[],bt=m.boot||{};h+=`<div class=card><b>Drive health</b><p><button class=a onclick="act('hardware')">Check hardware and backups</button></p>`;
h+=dh.available?'<table><tr><th>Drive</th><th>Status</th><th>Temperature</th><th>Details</th></tr>'+dh.devices.map(d=>`<tr><td>${esc(d.name)}</td><td class=${d.healthy===true?'ok':d.healthy===false?'bad':''}>${esc(d.status)}</td><td>${d.temperature_c==null?'n/a':esc(d.temperature_c)+' C'}</td><td>${esc((d.problems||[]).join('; '))}</td></tr>`).join('')+'</table>':`<div class=mut>${esc(dh.note||'SMART scan has not completed or is unavailable.')}</div>`;
h+=`<p class=mut>Disk activity: read ${m.disk_read_mbps??'-'} MB/s | write ${m.disk_write_mbps??'-'} MB/s${m.disk_busy_percent!=null?' | busy '+m.disk_busy_percent+'%':''}</p></div>`;
h+='<div class=card><b>Backups</b>'+(bs.length?'<table><tr><th>Path</th><th>Last backup</th><th>Age</th><th>Status</th></tr>'+bs.map(b=>`<tr><td>${esc(b.path)}</td><td>${esc(b.last_backup||'not found')}</td><td>${b.age_days==null?'n/a':esc(b.age_days)+' days'}</td><td class=${b.fresh?'ok':'bad'}>${b.fresh?'Fresh':'Stale or missing'}</td></tr>`).join('')+'</table>':'<div class=mut>Set backup_paths in Settings to monitor backup files or folders.</div>')+'</div>';
h+='<div class=card><b>Cooling and throttling</b><div class=mut>'+(m.throttle_count==null?'CPU throttle counter unavailable':'Thermal throttle events: '+esc(m.throttle_count))+(m.cpu_speed_limit_percent==null?'':' | CPU speed limit: '+esc(m.cpu_speed_limit_percent)+'%')+'</div>'+(m.fan_speeds&&m.fan_speeds.length?'<table><tr><th>Fan</th><th>Speed</th></tr>'+m.fan_speeds.map(f=>`<tr><td>${esc(f.name)}</td><td>${f.rpm==null?'n/a':esc(f.rpm)+' RPM'}</td></tr>`).join('')+'</table>':'<div class=mut>Fan speed sensors unavailable on this device.</div>')+'</div>';
h+='<div class=card><b>GPU</b>'+((m.gpus||[]).length?'<table><tr><th>GPU</th><th>Load</th><th>Temp</th><th>Memory</th></tr>'+m.gpus.map(g=>`<tr><td>${esc(g.name)}</td><td>${g.util}%</td><td>${g.temp} C</td><td>${g.mem_used_mb}/${g.mem_total_mb} MB</td></tr>`).join('')+'</table>':'<div class=mut>No NVIDIA GPU detected (needs nvidia-smi).</div>')+'</div>';
h+='<div class=card><b>Boot and startup</b><div class=mut>'+(bt.boot_seconds?'Last boot took '+esc(bt.boot_seconds)+' seconds':'Boot time unavailable')+'</div>'+((bt.slowest||[]).length?'<table><tr><th>Slowest services</th><th>Time</th></tr>'+bt.slowest.map(s=>`<tr><td>${esc(s.name)}</td><td>${esc(s.time)}</td></tr>`).join('')+'</table>':'')+'<p class=mut>Startup items: '+esc((bt.startup_items||[]).join(', ')||'none found')+'</p></div>';
const sv=m.services||[];if(sv.length)h+='<div class=card><b>Watched services</b><table>'+sv.map(s=>`<tr><td>${esc(s.name)}</td><td class=${s.state==='running'?'ok':s.state==='stopped'?'bad':''}>${esc(s.state)}</td></tr>`).join('')+'</table></div>'}
if(tab==='Network'){const sp=m.speedtests||[];h+=`<div class=card><b>Connection</b><div class=big>${m.network_ok?'<span class=ok>Online</span>':'<span class=bad>Offline</span>'}</div><div class=mut>${m.network_latency_ms==null?'latency unavailable':m.network_latency_ms+' ms average'} | ${m.network_loss_percent||0}% probe loss${m.wifi_signal_percent!=null?' | Wi-Fi '+m.wifi_signal_percent+'% ('+esc(m.wifi_ssid||'')+')':''}</div><div class=mut>Current traffic: down ${m.net_down_mbps??'-'} Mbps, up ${m.net_up_mbps??'-'} Mbps</div><p><button class=a onclick="act('speedtest')">Run speed test now</button></p></div>`;
h+='<div class=card><b>Speed tests</b>'+(sp.length?'<table><tr><th>Time</th><th>Download</th><th>Upload</th></tr>'+sp.slice().reverse().map(s=>`<tr><td>${esc(s.time)}</td><td>${s.download_mbps!=null?esc(s.download_mbps)+' Mbps':'<span class=bad>'+esc(s.error||'failed')+'</span>'}</td><td>${s.upload_mbps!=null?esc(s.upload_mbps)+' Mbps':'n/a'}</td></tr>`).join('')+'</table>':'<div class=mut>No speed test yet (see speedtest_enabled in Settings).</div>')+'</div>';
if(cn.available===false)h+=`<div class=card><b>Connections</b><div class=mut>${esc(cn.note||'Connection scanning is disabled.')}</div></div>`;else{
h+='<div class=card><b>Programs using the network</b>'+((cn.top||[]).length?'<table><tr><th>Program</th><th>Open connections</th></tr>'+cn.top.map(x=>`<tr><td>${esc(x.name)}</td><td>${esc(x.connections)}</td></tr>`).join('')+'</table>':'<div class=mut>No data yet.</div>')+'</div>';
h+='<div class=card><b>Open ports (listening)</b><div class=mut>"Exposed" means reachable from other computers.</div>'+((cn.listeners||[]).length?'<table><tr><th>Program</th><th>Port</th><th>Address</th><th></th></tr>'+cn.listeners.map(l=>`<tr><td>${esc(l.process)}</td><td>${esc(l.port)}</td><td>${esc(l.address)}</td><td class=${l.exposed?'warnc':'mut'}>${l.exposed?'exposed':'local only'}</td></tr>`).join('')+'</table>':'<div class=mut>None found.</div>')+'</div>'}
const nf=is.filter(x=>x.key.startsWith('net:'));h+='<div class=card><b>Suspicious connections</b>'+(nf.length?nf.map(issueHtml).join(''):'<div class=ok>Nothing suspicious.</div>')+'</div>'}
if(tab==='Security'){const sf=is.filter(x=>x.key.startsWith('mal:')||x.key.startsWith('canary:')||x.key.startsWith('integrity:')||x.key.startsWith('usb:')||x.key.startsWith('logins:')),cy=m.canary||{},ig=m.integrity||{};
h+=`<div class=card><b>Protection status</b><p>${esc(sc.summary||'Scan has not finished yet.')}</p><div class=mut>Last scan: ${esc(sc.last_scan||'-')}</div><p><button class=a onclick="act('scan')">Scan now</button></p></div>`;
h+='<div class=card><b>Findings</b>'+(sf.length?sf.map(issueHtml).join(''):'<div class=ok>Nothing suspicious found.</div>')+'</div>';
h+='<div class=card><b>Ransomware canary files</b><div class=mut>Decoy files in Documents/Desktop. If anything changes them, you get a critical alert.</div>'+(cy.enabled?'<table>'+(cy.files||[]).map(f=>`<tr><td>${esc(f.path)}</td><td class=${f.ok?'ok':'bad'}>${f.ok?'intact':'TAMPERED'}</td></tr>`).join('')+'</table>':'<div class=mut>Disabled (canary_enabled in Settings).</div>')+'</div>';
h+='<div class=card><b>File integrity</b>'+(ig.enabled?`<div class=mut>${esc(ig.files)} files watched${ig.limited?' (limit reached)':''} | last check ${esc(ig.checked||'-')}</div><p class=mut>Modified: ${esc((ig.modified||[]).join(', ')||'none')}<br>New: ${esc((ig.new||[]).join(', ')||'none')}<br>Removed: ${esc((ig.removed||[]).join(', ')||'none')}</p><button class="a s" onclick="if(confirm('Treat the current state of these files as correct?'))act('integrity_accept')">Accept changes</button>`:'<div class=mut>Add folders to integrity_paths in Settings to watch them.</div>')+'</div>';
h+=`<div class=card><b>USB devices</b><div class=mut>You are alerted when a new one appears.</div><p class=mut>${esc((m.usb_devices||[]).join(' | ')||'none detected')}</p></div>`;
h+=`<div class=card><b>Failed sign-ins (last hour)</b><div class=big>${m.failed_logins==null?'n/a':m.failed_logins}</div><div class=mut>${m.failed_logins==null?'Not available (needs administrator rights on Windows).':''}</div></div>`;
h+=`<div class=card><b>Hash blocklist</b><div class=mut>Paste a SHA-256 of a known-bad file; any running program matching it is flagged critical.</div><div class=row><input id=bh placeholder="64-character SHA-256"><button class=a onclick="act('blocklist',$('bh').value)">Add</button></div></div>`;
h+=`<div class=card><b>Ignored processes</b><p class=mut>${esc((CFG.ignore_process_names||[]).join(', ')||'none (edit under Settings)')}</p></div>`}
if(tab==='Updates'){h+=`<div class=card><div class=big>${u.checked?u.count+' pending':'Checking...'}</div><div class=mut>${u.security||0} security - ${u.reboot?'<b>restart required</b>':'no restart needed'} - last check ${esc(u.checked||'-')}</div>${u.error?'<p class=bad>'+esc(u.error)+'</p>':''}<p><button class=a onclick="act('updates')">Check now</button></p></div>`;
h+='<div class=card><b>Available OS updates</b>'+((u.titles||[]).length?'<table>'+u.titles.map(t=>`<tr><td>${esc(t)}</td></tr>`).join('')+'</table>':'<p class=ok>None reported.</p>')+'</div>';
const au=m.app_updates||{};h+='<div class=card><b>Application updates</b><div class=mut>'+(!au.available?'Supported package manager unavailable':au.count+' update(s) found')+'</div>'+(au.apps&&au.apps.length?'<table><tr><th>Application</th><th>Installed</th><th>Available</th></tr>'+au.apps.map(a=>`<tr><td>${esc(a.name||a.id)}</td><td>${esc(a.current||'unknown')}</td><td>${esc(a.latest||'unknown')}</td></tr>`).join('')+'</table>':'')+'</div>'}
if(tab==='Processes')h+='<div class=cols>'+ptable('Top CPU',m.top_cpu,'cpu','%')+ptable('Top memory',m.top_mem,'mem','%')+ptable('Most network connections',cn.top,'connections','')+'</div>'+((is.filter(x=>x.key.startsWith('leak:'))).length?'<div class=card><b>Possible memory leaks</b>'+is.filter(x=>x.key.startsWith('leak:')).map(issueHtml).join('')+'</div>':'');
if(tab==='History'){h+=rangeBar()+`<div class=cols>${chart('CPU %','cpu','var(--acc)')}${chart('Memory %','ram','var(--warn)')}${chart('Health score','score','var(--ok)')}${chart('Battery %','battery','var(--ok)')}${chart('Battery health %','battery_health','var(--warn)')}${chart('Network latency','network_latency','var(--acc)',true,' ms')}${chart('Temperature','temperature','var(--bad)',true,' C')}${chart('GPU load %','gpu','var(--acc)')}${chart('Wi-Fi signal %','wifi','var(--ok)')}</div>`;
h+='<div class=card><b>Spikes: what was running</b><div class=mut>High CPU or memory periods in this range, with the biggest programs at the worst moment.</div>'+(SP.length?'<table><tr><th>When</th><th>Peak</th><th>Top CPU</th><th>Top memory</th></tr>'+SP.map(s=>`<tr><td>${esc(s.start.replace('T',' '))}${s.end!==s.start?' &rarr; '+esc(s.end.slice(11)):''}</td><td>CPU ${esc(Math.round(s.peak_cpu))}% / RAM ${esc(Math.round(s.peak_ram))}%</td><td>${esc((s.top_cpu||[]).map(x=>x[0]+' '+x[1]+'%').join(', '))}</td><td>${esc((s.top_mem||[]).map(x=>x[0]+' '+x[1]+'%').join(', '))}</td></tr>`).join('')+'</table>':'<div class=ok>No spikes in this range.</div>')+'</div>'}
if(tab==='Devices'){if(!DEV.enabled)h+='<div class=card><b>Multi-device hub is off</b><p class=mut>Hub computer: set hub_enabled=true, hub_token=(a long secret), dashboard_host=0.0.0.0 and a dashboard_password, then restart. Other computers: set hub_url (for example http://192.168.1.10:8765) and the same hub_token. Traffic is plain HTTP, so use this only on a network you trust.</p></div>';else{
h+=(DEV.token_set?'':'<div class=card><b class=bad>hub_token is empty</b><div class=mut>Other computers cannot report until you set it in Settings.</div></div>')+'<div class=card><b>Computers</b><table><tr><th>Name</th><th>Status</th><th>Score</th><th>CPU</th><th>RAM</th><th>Disk</th><th>Battery</th><th>Issues</th></tr>'+(DEV.devices||[]).map(d=>`<tr><td>${esc(d.name)}${d.this_device?' <span class=mut>(this hub)</span>':''}<div class=mut>${esc(d.os)}</div></td><td class=${d.online?'ok':'bad'}>${d.online?'online':'offline '+Math.round(d.age/60)+' min'}</td><td>${d.score==null?'-':esc(d.score)}</td><td>${d.cpu==null?'-':Math.round(d.cpu)+'%'}</td><td>${d.ram==null?'-':Math.round(d.ram)+'%'}</td><td>${d.disk==null?'-':Math.round(d.disk)+'%'}</td><td>${d.battery==null?'-':esc(d.battery)+'%'}</td><td>${(d.issues||[]).length?'<details><summary>'+d.issues.length+'</summary>'+d.issues.map(i=>'<div class=mut>['+esc(i.severity)+'] '+esc(i.message)+'</div>').join('')+'</details>':'<span class=ok>none</span>'}</td></tr>`).join('')+'</table></div>'}}
if(tab==='Alerts'){h+=`<div class=card><b>Active alerts</b>${is.length?is.map(issueHtml).join(''):'<div class=ok>All clear.</div>'}<p><button class="a s" onclick="act('test')">Send test notification</button></p></div><div class=card><b>Log</b><pre>${esc(LOG||'(empty)')}</pre></div>`}
if(tab==='Settings'){h+=`<div class=card><b>Maintenance</b><div class=mut>Safe clean-ups you can run any time. Close your browser first for the cache clean-up.</div><p class=row><button class="a s" onclick="if(confirm('Delete temp files older than 7 days?'))act('fix','temp')">Clean old temp files</button><button class="a s" onclick="if(confirm('Clear browser caches? (Cookies and passwords are not touched.)'))act('fix','browser_cache')">Clear browser caches</button><button class="a s" onclick="if(confirm('Permanently empty the recycle bin / trash?'))act('fix','recycle_bin')">Empty recycle bin</button><button class="a s" onclick="act('fix','dns')">Flush DNS</button><button class="a s" onclick="if(confirm('Remove and re-create the canary files?'))act('canary_reset')">Reset canaries</button></p><p class=row><button class=a onclick="if(confirm('Start DeviceWatch automatically when you log in?'))act('startup_install')">Run at startup</button><button class="a s" onclick="act('startup_remove')">Remove from startup</button></p></div>`;
h+=`<div class=card><b>Settings</b><div class=mut>Saved to the config file. Interval, port, host and scan-schedule changes apply after restart. Secrets are hidden; leave them as they are to keep them.</div>${fields(CFG)}<p class=row><button class=a onclick="save()">Save settings</button></p></div>`}
return h}
function draw(){const m=S.metrics||{};if(m.time){$('host').textContent=m.host;$('sub').textContent=m.os+' - updated '+m.time;$('sc').textContent=S.score;const r=$('ring');r.setAttribute('stroke-dasharray',S.score*2.64+' 264');r.setAttribute('stroke',S.score>=80?'var(--ok)':S.score>=50?'var(--warn)':'var(--bad)')}
$('nav').innerHTML=TABS.map(t=>`<button class="${t===tab?'on':''}" onclick="tab='${t}';load(true)">${t}</button>`).join('');if(!(tab==='Settings'&&editing))$('main').innerHTML=view()}
async function load(force){try{S=await api('/api/status');
if(tab==='Overview'||tab==='History')H=await api('/api/history?range='+RANGE);
if(tab==='History')SP=await api('/api/spikes?range='+RANGE);
if(tab==='Devices')DEV=await api('/api/devices');
if(tab==='Alerts')LOG=(await api('/api/log')).log;
if(tab==='Settings'&&(force||!Object.keys(CFG).length)){CFG=await api('/api/config');editing=false}else if(!CFG.interval_seconds)CFG=await api('/api/config');
draw();if(tab==='Settings')editing=true}catch(e){}}
load(true);setInterval(()=>load(),5000);
</script></body></html>"""


def do_action(mon, name, arg):
    try:
        if name == "scan":
            mon.security_scan()
            mon.connection_scan()
            mon.tick()
            return {"msg": "Security scan finished"}
        if name == "updates":
            def check_updates_now():
                mon.update_scan()
                mon.app_update_scan()
                mon.tick()
            threading.Thread(target=check_updates_now, daemon=True).start()
            return {"msg": "Checking OS and application updates..."}
        if name == "hardware":
            def check_hardware_now():
                mon.disk_health_scan()
                mon.backup_scan()
                mon.tick()
            threading.Thread(target=check_hardware_now, daemon=True).start()
            return {"msg": "Checking drive health and backup freshness..."}
        if name == "speedtest":
            threading.Thread(target=lambda: mon.speed_scan(force=True), daemon=True).start()
            return {"msg": "Running speed test (about 10-20 seconds)..."}
        if name == "fix":
            if arg not in ("temp", "browser_cache", "recycle_bin", "dns"):
                return {"msg": "Unknown fix"}
            return {"msg": mon.run_fix(arg)}
        if name == "integrity_accept":
            mon.integrity_accept()
            return {"msg": "Current file state accepted as the new baseline"}
        if name == "canary_reset":
            mon.canary_reset()
            return {"msg": "Canary files re-created"}
        if name == "startup_install":
            return {"msg": install_startup()[1]}
        if name == "startup_remove":
            return {"msg": uninstall_startup()[1]}
        if name == "test":
            mon.broadcast("DeviceWatch", "DeviceWatch test alert - alerts are working.", desktop=True)
            return {"msg": "Test alert sent"}
        if name == "ignore":
            names = mon.cfg["ignore_process_names"]
            if arg not in names:
                names.append(arg)
            save_config(mon.cfg)
            mon.sticky.clear()
            return {"msg": f"Ignoring '{arg}' from now on"}
        if name == "blocklist":
            h = str(arg).strip().lower()
            if len(h) != 64 or any(ch not in "0123456789abcdef" for ch in h):
                return {"msg": "That is not a valid SHA-256 hash"}
            with open(BLOCKLIST_PATH, "a") as f:
                f.write(h + "\n")
            return {"msg": "Added to blocklist"}
        if name == "kill":
            pid = int(arg)
            if pid in (os.getpid(), 0, 4):
                return {"msg": "Refusing to end that process"}
            p = psutil.Process(pid)
            nm = p.name()
            p.terminate()
            return {"msg": f"Ended {nm}"}
    except Exception as e:
        return {"msg": f"Failed: {e}"}
    return {"msg": "Unknown action"}


def start_dashboard(mon, port):
    cfg = mon.cfg
    host = str(cfg.get("dashboard_host") or "127.0.0.1")
    if host in ("localhost", "::1"):
        host = "127.0.0.1"
    loopback = host == "127.0.0.1"
    if not loopback and not cfg.get("dashboard_password"):
        print("dashboard_host is not local but dashboard_password is empty - refusing to expose the dashboard. "
              "Using 127.0.0.1 instead.")
        host, loopback = "127.0.0.1", True
    token = secrets.token_hex(16)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}   # blocks DNS-rebinding attacks (local mode)
    cache = {}

    def cached(key, ttl, fn):
        hit = cache.get(key)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
        val = fn()
        cache[key] = (time.time(), val)
        return val

    class Handler(BaseHTTPRequestHandler):
        def send(self, obj, code=200, ctype="application/json", extra=None):
            body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def host_ok(self):
            return (not loopback) or self.headers.get("Host") in allowed_hosts

        def authed(self):
            pw = cfg.get("dashboard_password", "")
            if not pw:
                return True
            hdr = self.headers.get("Authorization", "")
            if hdr.startswith("Basic "):
                try:
                    given = base64.b64decode(hdr[6:]).decode("utf-8", "replace").split(":", 1)[1]
                except (ValueError, IndexError):
                    return False
                return secrets.compare_digest(given.encode(), pw.encode())
            return False

        def deny(self):
            self.send({"error": "unauthorized"}, 401, extra={"WWW-Authenticate": 'Basic realm="DeviceWatch"'})

        def do_GET(self):
            if not self.host_ok():
                return self.send({"error": "forbidden"}, 403)
            if not self.authed():
                return self.deny()
            url = urllib.parse.urlparse(self.path)
            path, q = url.path, urllib.parse.parse_qs(url.query)
            rng = q.get("range", ["1h"])[0]
            hours = RANGES.get(rng, 1)
            if path == "/api/status":
                self.send(mon.latest)
            elif path == "/api/history":
                self.send(cached(("h", rng), 5 if hours <= 1 else 60, lambda: read_history(hours, 240)))
            elif path == "/api/spikes":
                self.send(cached(("s", rng), 30, lambda: find_spikes(hours, cfg)))
            elif path == "/api/log":
                try:
                    self.send({"log": "\n".join(LOG_PATH.read_text().splitlines()[-80:])})
                except Exception:
                    self.send({"log": ""})
            elif path == "/api/config":
                self.send(public_config(cfg))
            elif path == "/api/devices":
                self.send(mon.devices_view())
            elif path == "/report":
                if not mon.latest.get("metrics"):
                    mon.tick()
                self.send(build_report_html(mon).encode(), 200, "text/html; charset=utf-8")
            else:
                self.send(PAGE.replace("__TOKEN__", token).encode(), 200, "text/html; charset=utf-8")

        def read_json(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length > 1_000_000:
                raise ValueError("too large")
            return json.loads(self.rfile.read(length) or b"{}")

        def do_POST(self):
            if not self.host_ok():
                return self.send({"msg": "Forbidden"}, 403)
            try:
                data = self.read_json()
            except ValueError:
                return self.send({"msg": "Bad request"}, 400)
            if self.path == "/api/push":                       # other computers reporting in
                want = cfg.get("hub_token", "")
                got = self.headers.get("X-Hub-Token", "")
                if not (cfg.get("hub_enabled") and want and secrets.compare_digest(got.encode(), want.encode())):
                    return self.send({"msg": "Forbidden"}, 403)
                if not isinstance(data, dict):
                    return self.send({"msg": "Bad request"}, 400)
                status = sanitize_status(data)
                if status["name"] in mon.devices or len(mon.devices) < 200:
                    mon.devices[status["name"]] = dict(status, received=time.time())
                return self.send({"msg": "ok"})
            if not self.authed():
                return self.deny()
            if self.headers.get("X-Token") != token:
                return self.send({"msg": "Forbidden"}, 403)
            if self.path == "/api/action":
                return self.send(do_action(mon, data.get("name"), data.get("arg")))
            if self.path == "/api/config":
                if isinstance(data, dict):
                    apply_config(cfg, data)
                    save_config(cfg)
                return self.send({"msg": "Settings saved"})
            self.send({"msg": "Not found"}, 404)

        def log_message(self, *a):
            pass

    try:
        srv = ThreadingHTTPServer((host, port), Handler)
    except OSError as e:
        print(f"Dashboard not started on port {port}: {e}")
        return None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    shown = "127.0.0.1" if host in ("127.0.0.1", "0.0.0.0") else host
    print(f"Interface: http://{shown}:{port}" + ("  (also reachable from your network; password protected)" if not loopback else ""))
    return f"http://{shown}:{port}"


# --------------------------------------------------- start at login / tray icon
def startup_command():
    if getattr(sys, "frozen", False):
        return [sys.executable, "--no-browser"]
    exe = sys.executable
    if OS == "Windows":
        pw = Path(exe).with_name("pythonw.exe")
        if pw.exists():
            exe = str(pw)
    return [exe, str(Path(__file__).resolve()), "--no-browser"]


def _refresh_autostart_baseline():
    """Our own startup entry must not trigger the 'new startup item' alert."""
    with STATE_LOCK:
        st = load_state()
        st["autostart"] = sorted(autostart_entries())
        save_state(st)


def install_startup():
    cmd = startup_command()
    try:
        if OS == "Windows":
            tr = " ".join(f'"{c}"' if not c.startswith("--") else c for c in cmd)
            r = subprocess.run(["schtasks", "/create", "/tn", "DeviceWatch", "/tr", tr, "/sc", "onlogon",
                                "/rl", "limited", "/f"], capture_output=True, text=True, errors="replace",
                               creationflags=CREATE_NO_WINDOW)
            ok = r.returncode == 0
            msg = "DeviceWatch will start when you log in." if ok else (r.stderr or r.stdout).strip()
        elif OS == "Darwin":
            plist = Path.home() / "Library/LaunchAgents/com.devicewatch.agent.plist"
            plist.parent.mkdir(parents=True, exist_ok=True)
            with open(plist, "wb") as f:
                plistlib.dump({"Label": "com.devicewatch.agent", "ProgramArguments": cmd,
                               "RunAtLoad": True, "KeepAlive": True}, f)
            run(["launchctl", "load", "-w", str(plist)], 15)
            ok, msg = True, "DeviceWatch will start when you log in."
        else:
            unit_dir = Path.home() / ".config/systemd/user"
            if shutil_which("systemctl"):
                unit_dir.mkdir(parents=True, exist_ok=True)
                (unit_dir / "devicewatch.service").write_text(
                    "[Unit]\nDescription=DeviceWatch\n\n[Service]\nExecStart=" + shlex.join(cmd) +
                    "\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n")
                run(["systemctl", "--user", "daemon-reload"], 15)
                run(["systemctl", "--user", "enable", "--now", "devicewatch.service"], 30)
            else:
                auto = Path.home() / ".config/autostart"
                auto.mkdir(parents=True, exist_ok=True)
                (auto / "devicewatch.desktop").write_text(
                    "[Desktop Entry]\nType=Application\nName=DeviceWatch\nExec=" + shlex.join(cmd) + "\n")
            ok, msg = True, "DeviceWatch will start when you log in."
        if ok:
            _refresh_autostart_baseline()
        return ok, msg
    except Exception as e:
        return False, f"Could not set up auto-start: {e}"


def uninstall_startup():
    try:
        if OS == "Windows":
            subprocess.run(["schtasks", "/delete", "/tn", "DeviceWatch", "/f"], capture_output=True,
                           creationflags=CREATE_NO_WINDOW)
        elif OS == "Darwin":
            plist = Path.home() / "Library/LaunchAgents/com.devicewatch.agent.plist"
            run(["launchctl", "unload", "-w", str(plist)], 15)
            plist.unlink(missing_ok=True)
        else:
            run(["systemctl", "--user", "disable", "--now", "devicewatch.service"], 30)
            (Path.home() / ".config/systemd/user/devicewatch.service").unlink(missing_ok=True)
            (Path.home() / ".config/autostart/devicewatch.desktop").unlink(missing_ok=True)
        _refresh_autostart_baseline()
        return True, "Removed from startup."
    except Exception as e:
        return False, f"Could not remove auto-start: {e}"


def tray_available():
    try:
        import pystray  # noqa: F401
        from PIL import Image  # noqa: F401
        return True
    except ImportError:
        return False


def run_tray(mon, url, stop):
    import pystray
    from PIL import Image, ImageDraw

    def make_icon(score):
        color = (22, 163, 74) if score >= 80 else (217, 119, 6) if score >= 50 else (220, 38, 38)
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        ImageDraw.Draw(img).ellipse((4, 4, 60, 60), fill=color)
        return img

    def quit_app(icon, item=None):
        stop.set()
        icon.stop()

    icon = pystray.Icon("DeviceWatch", make_icon(100), "DeviceWatch", menu=pystray.Menu(
        pystray.MenuItem("Open dashboard", lambda icon, item: url and webbrowser.open(url), default=True),
        pystray.MenuItem("Scan now", lambda icon, item: threading.Thread(
            target=lambda: (mon.security_scan(), mon.tick()), daemon=True).start()),
        pystray.MenuItem("Quit", quit_app)))

    def refresh():
        while not stop.is_set():
            score = mon.latest.get("score", 100)
            icon.icon, icon.title = make_icon(score), f"DeviceWatch - health {score}/100"
            time.sleep(15)
    threading.Thread(target=refresh, daemon=True).start()
    icon.run()


def print_report(res):
    m = res["metrics"]
    print(f"\n=== DeviceWatch report - {m['host']} ({m['os']}) ===")
    print(f"Health score: {res['score']}/100")
    print(f"CPU {m['cpu_percent']}% | RAM {m['ram_percent']}% ({m['ram_used_gb']}/{m['ram_total_gb']} GB) | uptime {m['uptime_days']}d")
    for d in m["disks"]:
        print(f"Disk {d['mount']}: {d['percent']}% used, {d['free_gb']} GB free")
    if "battery_percent" in m:
        print(f"Battery: {m['battery_percent']}% ({'charging' if m['battery_plugged'] else 'on battery'})")
    if "battery_health_percent" in m:
        detail = f"{m.get('battery_health_label', 'health unknown')}, {m['battery_wear_percent']}% wear"
        if "battery_cycle_count" in m:
            detail += f", {m['battery_cycle_count']} cycles"
        print(f"Battery health: {m['battery_health_percent']}% ({detail})")
    if "max_temp_c" in m:
        print(f"Temperature: {m['max_temp_c']} C")
    for g in m.get("gpus", []):
        print(f"GPU {g['name']}: {g['util']}% load, {g['temp']} C")
    network_detail = "latency unavailable" if m.get("network_latency_ms") is None else f"{m['network_latency_ms']} ms, {m['network_loss_percent']}% probe loss"
    print(f"Network: {'online' if m['network_ok'] else 'OFFLINE'} ({network_detail})")
    if m.get("wifi_signal_percent") is not None:
        print(f"Wi-Fi signal: {m['wifi_signal_percent']}% ({m.get('wifi_ssid', '')})")
    if m.get("speedtests"):
        s = m["speedtests"][-1]
        print(f"Speed test: {s.get('download_mbps', 'n/a')} Mbps down / {s.get('upload_mbps', 'n/a')} Mbps up")
    disk_health = m.get("disk_health") or {}
    for device in disk_health.get("devices", []):
        print(f"Drive health: {device['name']} - {device['status']}" +
              (f" ({'; '.join(device['problems'])})" if device.get("problems") else ""))
    for backup in m.get("backups", []):
        age = "not found" if backup["age_days"] is None else f"{backup['age_days']} days old"
        print(f"Backup: {backup['path']} - {age}")
    apps = m.get("app_updates") or {}
    if apps.get("available"):
        print(f"Application updates: {apps['count']} available")
    if m.get("throttle_count") is not None:
        print(f"Thermal throttle events: {m['throttle_count']}")
    if m.get("cpu_speed_limit_percent") is not None:
        print(f"CPU speed limit: {m['cpu_speed_limit_percent']}%")
    if m.get("fan_speeds"):
        print("Fans:", ", ".join(f"{fan['name']} {fan['rpm'] if fan['rpm'] is not None else 'n/a'} RPM"
                                for fan in m["fan_speeds"]))
    boot = m.get("boot") or {}
    if boot.get("boot_seconds"):
        print(f"Last boot time: {boot['boot_seconds']} seconds")
    if m.get("failed_logins") is not None:
        print(f"Failed sign-ins (last hour): {m['failed_logins']}")
    if m.get("usb_devices"):
        print("USB devices:", "; ".join(m["usb_devices"]))
    print("Top CPU:", ", ".join(f"{p['name']} {p['cpu']}%" for p in m["top_cpu"][:3]))
    print("Top RAM:", ", ".join(f"{p['name']} {p['mem']}%" for p in m["top_mem"][:3]))
    sec, up = m.get("security") or {}, m.get("updates") or {}
    if sec:
        print("Security:", sec.get("summary", "n/a"))
    if up.get("checked"):
        print(f"Updates: {up['count']} pending ({up['security']} security)" + (" - restart required" if up["reboot"] else ""))
    if res["issues"]:
        print("\nProblems found:")
        for i in res["issues"]:
            print(f" [{i['severity'].upper()}] {i['message']}\n     Fix: {i['fix']}")
    else:
        print("\nNo problems detected.")


def monitor_loop(mon, cfg, stop):
    while not stop.is_set():
        try:
            res = mon.tick()
            logging.info("score=%s cpu=%s%% ram=%s%% issues=%d", res["score"],
                         res["metrics"]["cpu_percent"], res["metrics"]["ram_percent"], len(res["issues"]))
        except Exception:
            logging.exception("Check failed")
        for _ in range(int(cfg["interval_seconds"])):
            if stop.is_set():
                break
            time.sleep(1)


def main():
    ap = argparse.ArgumentParser(description="DeviceWatch - device health monitor")
    ap.add_argument("--once", action="store_true", help="run one check, print a report, exit")
    ap.add_argument("--report", action="store_true", help="run one check, save an HTML report, exit")
    ap.add_argument("--init", action="store_true", help="write a default config file and exit")
    ap.add_argument("--no-dashboard", action="store_true")
    ap.add_argument("--no-browser", action="store_true", help="don't open the dashboard in your browser")
    ap.add_argument("--tray", action="store_true", help="show a system-tray icon (needs pystray + pillow)")
    ap.add_argument("--install-startup", action="store_true", help="start DeviceWatch automatically at login")
    ap.add_argument("--uninstall-startup", action="store_true", help="remove the auto-start entry")
    args = ap.parse_args()

    HOME.mkdir(exist_ok=True)
    if args.init:
        if not CONFIG_PATH.exists():
            save_config(DEFAULT_CONFIG)
        print(f"Edit your settings in: {CONFIG_PATH}")
        return
    if args.install_startup or args.uninstall_startup:
        ok, msg = install_startup() if args.install_startup else uninstall_startup()
        print(msg)
        sys.exit(0 if ok else 1)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()])
    cfg = load_config()
    mon = Monitor(cfg)

    if args.once or args.report:
        print("Running health, security, hardware, backup, network and update checks (some may take a few minutes)...")
        mon.run_all_scans_once()
        res = mon.tick()
        if args.report:
            REPORT_DIR.mkdir(exist_ok=True)
            out = REPORT_DIR / f"devicewatch-report-{datetime.now():%Y%m%d-%H%M%S}.html"
            out.write_text(build_report_html(mon), encoding="utf-8")
            print(f"Report saved: {out}\nOpen it in a browser and use Print > Save as PDF if you need a PDF.")
        else:
            print_report(res)
        return

    prune_history(cfg.get("history_days", 30))
    dashboard_url = None
    if not args.no_dashboard:
        dashboard_url = start_dashboard(mon, cfg["dashboard_port"])
    mon.dashboard_url = dashboard_url
    mon.start_background()
    if dashboard_url and not args.no_browser and not args.tray:
        try:
            mon.tick()  # take one reading first so the page isn't blank on load
        except Exception:
            logging.exception("First check failed")
        webbrowser.open(dashboard_url)
    logging.info("DeviceWatch started (checking every %ss). Ctrl+C to stop.", cfg["interval_seconds"])

    stop = threading.Event()
    if args.tray and not tray_available():
        print("Tray icon needs:  pip install pystray pillow   - continuing without it.")
    if args.tray and tray_available():
        threading.Thread(target=monitor_loop, args=(mon, cfg, stop), daemon=True).start()
        try:
            run_tray(mon, dashboard_url, stop)      # blocks until you choose Quit
        except KeyboardInterrupt:
            pass
        stop.set()
        return
    try:
        monitor_loop(mon, cfg, stop)
    except KeyboardInterrupt:
        stop.set()
        print("\nStopped.")


if __name__ == "__main__":
    main()