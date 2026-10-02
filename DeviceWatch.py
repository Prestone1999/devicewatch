#!/usr/bin/env python3
"""
DeviceWatch - automated health monitoring for your laptop / PC.

Monitors: CPU, RAM, swap, SMART disk health, configured backup freshness,
          temperature/fans, battery status/health/history, network quality, uptime,
          resource-hogging processes and recent system errors.
Security: antivirus/firewall status, suspicious processes (miners, fake system
          processes, programs running from temp/download folders), new startup
          items, hosts-file tampering, optional hash blocklist + VirusTotal lookup.
Updates:  pending OS and supported package-manager application updates.
Acts:     desktop notifications, email, webhook (Slack/Discord/Telegram-style),
          log + history files, live local dashboard, optional safe auto-fix.

Setup:    pip install psutil
Run:      python devicewatch.py                 (monitor + dashboard, opens your browser)
          python devicewatch.py --no-browser    (monitor + dashboard, browser stays closed)
          python devicewatch.py --once          (one-off health report, then exit)
          python devicewatch.py --init          (write an editable config file)
"""
import argparse
import hashlib
import json
import logging
import os
import platform
import re
import secrets
import smtplib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import webbrowser
import xml.etree.ElementTree as ET
from collections import deque
from datetime import datetime
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
OS = platform.system()  # Windows / Darwin / Linux

DEFAULT_CONFIG = {
    "interval_seconds": 30,
    "cpu_percent": 90,
    "cpu_sustained_samples": 4,        # consecutive samples above threshold
    "ram_percent": 90,
    "swap_percent": 80,
    "disk_percent": 90,
    "disk_free_gb_min": 5,
    "cpu_temp_c": 85,
    "battery_low_percent": 15,
    "battery_health_warn_percent": 70,
    "uptime_days_warn": 14,
    "network_check_host": "1.1.1.1",
    "network_check_port": 53,
    "network_probe_count": 3,
    "network_latency_warn_ms": 250,
    "backup_paths": [],                # backup files or directories to check
    "backup_max_age_days": 7,
    "backup_check_hours": 1,
    "scan_system_errors": True,
    "system_errors_per_hour_warn": 20,
    "scan_malware": True,
    "scan_interval_minutes": 10,       # how often the security scan runs
    "signature_max_age_days": 3,       # warn if antivirus definitions are older
    "ignore_process_names": [],        # e.g. ["myportableapp.exe"] to silence false positives
    "virustotal_api_key": "",          # optional: free key from virustotal.com (only file HASHES are sent)
    "check_updates": True,
    "update_check_hours": 6,
    "check_app_updates": True,
    "app_check_hours": 12,
    "check_disk_health": True,
    "disk_health_check_hours": 6,
    "alert_cooldown_minutes": 30,
    "desktop_notifications": True,
    "auto_fix": False,                 # if true: deletes temp files older than 7 days when disk is low
    "dashboard_port": 8765,
    "webhook_url": "",                 # POSTs {"text": "..."} (works with Slack / Discord-compatible hooks)
    "email": {
        "enabled": False,
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "username": "",
        "password": "",                # use an app password, not your real one
        "to": "",
    },
}


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


def gb(n):
    return round(n / 1024 ** 3, 1)


# ------------------------------------------------------------ security helpers
STATE_PATH = HOME / "security_state.json"
BLOCKLIST_PATH = HOME / "blocklist.txt"      # optional: one SHA-256 per line
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


def run(cmd, timeout=60):
    try:
        kw = {"creationflags": CREATE_NO_WINDOW} if CREATE_NO_WINDOW else {}
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw).stdout or ""
    except Exception:
        return ""


def ps(script, timeout=90):
    return run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout)


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


def shutil_which(cmd):
    import shutil
    return shutil.which(cmd)


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
    samples = max(1, min(5, int(cfg.get("network_probe_count", 3))))
    latencies = []
    failures = 0
    for _ in range(samples):
        started = time.perf_counter()
        try:
            with socket.create_connection((cfg["network_check_host"], cfg["network_check_port"]), timeout=1.5):
                latencies.append((time.perf_counter() - started) * 1000)
        except OSError:
            failures += 1
    return {"network_ok": bool(latencies),
            "network_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else None,
            "network_loss_percent": round(failures * 100 / samples)}


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
        psutil.cpu_percent(None)
        for p in psutil.process_iter():
            try:
                p.cpu_percent(None)
            except psutil.Error:
                pass

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

        # Disks
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
        thermal = thermal_status()
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

        # Network reachability and quality (bounded TCP probes)
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
        issues += [v[1] for _, v in list(self.sticky.items()) if v[0] > time.time()]
        m["security"], m["updates"] = self.sec_info, self.update_info
        m["disk_health"], m["app_updates"], m["backups"] = self.disk_info, self.app_info, self.backup_info

        # Health score
        penalty = {"critical": 25, "warning": 10, "notice": 5, "info": 3}
        score = max(0, 100 - sum(penalty[i["severity"]] for i in issues))
        return {"metrics": m, "issues": issues, "score": score}

    @staticmethod
    def count_system_errors():
        try:
            if OS == "Windows":
                q = "*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= 3600000]]]"
                out = subprocess.run(["wevtutil", "qe", "System", f"/q:{q}", "/f:xml", "/c:200"],
                                     capture_output=True, text=True, timeout=30).stdout
                return out.count("<Event ")
            if OS == "Linux":
                out = subprocess.run(["journalctl", "-p", "3", "--since", "1 hour ago", "--no-pager", "-q"],
                                     capture_output=True, text=True, timeout=30).stdout
                return len([l for l in out.splitlines() if l.strip()])
        except Exception:
            pass
        return None

    # -------------------------------------------------------------- security
    def load_state(self):
        try:
            return json.loads(STATE_PATH.read_text())
        except Exception:
            return {}

    def load_blocklist(self):
        try:
            return {l.split()[0].lower() for l in BLOCKLIST_PATH.read_text().splitlines()
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
        st = self.load_state()
        cur = autostart_entries()
        if "autostart" in st:
            for item in sorted(cur - set(st["autostart"])):
                add("warning", "mal:startup:" + item[:80], f"New program set to run automatically: {item}",
                    "If you didn't just install something, remove it (Windows: Task Manager > Startup / Task Scheduler) and run a full scan.",
                    sticky=True)
        else:
            logging.info("Security baseline created (%d startup items recorded).", len(cur))
        st["autostart"] = sorted(cur)
        hosts = (Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
                 if OS == "Windows" else Path("/etc/hosts"))
        try:
            hh = hashlib.sha256(hosts.read_bytes()).hexdigest()
            if st.get("hosts") and st["hosts"] != hh:
                add("warning", "mal:hosts", "Your hosts file was modified (malware uses this to redirect websites).",
                    f"Open {hosts} and remove entries you don't recognise.", sticky=True)
            st["hosts"] = hh
        except OSError:
            pass
        try:
            STATE_PATH.write_text(json.dumps(st))
        except OSError:
            pass

        info["summary"] = " | ".join(bits)
        info["suspicious"] = suspects
        info["last_scan"] = datetime.now().isoformat(timespec="seconds")
        self.sec_info, self.sec_issues = info, issues

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
                issues.append({"severity": "warning", "key": "disk:health:" + device["name"],
                               "message": f"Disk health warning for {device['name']}: {device['status']}"
                                          + (f" ({detail})" if detail else "."),
                               "fix": "Back up important files now and review the drive with its vendor diagnostics.",
                               })
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

    def start_background(self):
        def loop(fn, every):
            while True:
                try:
                    fn()
                except Exception:
                    logging.exception("%s failed", fn.__name__)
                time.sleep(every)
        threading.Thread(target=loop, args=(self.security_scan, self.cfg["scan_interval_minutes"] * 60), daemon=True).start()
        threading.Thread(target=loop, args=(self.update_scan, self.cfg["update_check_hours"] * 3600), daemon=True).start()
        threading.Thread(target=loop, args=(self.disk_health_scan,
                 self.cfg.get("disk_health_check_hours", 6) * 3600), daemon=True).start()
        threading.Thread(target=loop, args=(self.app_update_scan,
                 self.cfg.get("app_check_hours", 12) * 3600), daemon=True).start()
        threading.Thread(target=loop, args=(self.backup_scan,
                 self.cfg.get("backup_check_hours", 1) * 3600), daemon=True).start()

    # --------------------------------------------------------------- actions
    def auto_fix_disk(self):
        """Delete temp files older than 7 days. Only touches the OS temp directory."""
        cutoff, freed = time.time() - 7 * 86400, 0
        for f in Path(tempfile.gettempdir()).rglob("*"):
            try:
                if f.is_file() and f.stat().st_mtime < cutoff:
                    size = f.stat().st_size
                    f.unlink()
                    freed += size
            except Exception:
                continue
        logging.info("Auto-fix: freed %.1f MB of old temp files", freed / 1024 ** 2)
        return round(freed / 1024 ** 2, 1)

    def notify_desktop(self, title, msg):
        title, msg = title.replace('"', "'").replace("`", "'"), msg.replace('"', "'").replace("`", "'")
        try:
            if OS == "Windows":
                ps = ("[void][reflection.assembly]::LoadWithPartialName('System.Windows.Forms');"
                      "$n=New-Object System.Windows.Forms.NotifyIcon;"
                      "$n.Icon=[System.Drawing.SystemIcons]::Warning;$n.Visible=$true;"
                      f"$n.ShowBalloonTip(8000,'{title}','{msg}',[System.Windows.Forms.ToolTipIcon]::Warning);"
                      "Start-Sleep 9;$n.Dispose()")
                subprocess.Popen(["powershell", "-NoProfile", "-Command", ps],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
            logging.warning("Webhook failed: %s", ex)

    def dispatch(self, issues):
        base = self.cfg["alert_cooldown_minutes"] * 60
        long_keys = ("mal:startup", "mal:hosts", "update", "reboot", "app_updates", "backup:")
        fresh = []
        for i in issues:
            if i["severity"] == "info":
                continue
            cooldown = 86400 if i["key"].startswith(long_keys) else base
            if time.time() - self.last_alert.get(i["key"], 0) >= cooldown:
                self.last_alert[i["key"]] = time.time()
                fresh.append(i)
        if not fresh:
            return
        host = platform.node()
        text = "\n".join(f"[{i['severity'].upper()}] {i['message']}\n  -> {i['fix']}" for i in fresh)
        logging.warning("Alerts on %s:\n%s", host, text)
        if self.cfg["desktop_notifications"]:
            self.notify_desktop(f"DeviceWatch: {len(fresh)} issue(s)", "; ".join(i["message"] for i in fresh)[:240])
        self.send_email(f"[DeviceWatch] {len(fresh)} issue(s) on {host}", text)
        self.send_webhook(f"DeviceWatch on {host}:\n{text}")
        if self.cfg["auto_fix"] and any(i["key"].startswith("disk") for i in fresh):
            self.auto_fix_disk()

    def tick(self):
        self.latest = self.collect()
        with open(HISTORY_PATH, "a") as f:
            m = self.latest["metrics"]
            f.write(json.dumps({"t": m["time"], "score": self.latest["score"], "cpu": m["cpu_percent"],
                                "ram": m["ram_percent"], "battery": m.get("battery_percent"),
                                "battery_health": m.get("battery_health_percent"),
                                "network_latency": m.get("network_latency_ms"),
                                "temperature": m.get("max_temp_c"),
                                "issues": [i["key"] for i in self.latest["issues"]]}) + "\n")
        self.dispatch(self.latest["issues"])
        return self.latest


# ------------------------------------------------------------------ dashboard
PAGE = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DeviceWatch</title><style>
:root{--bg:#f4f5f7;--card:#fff;--tx:#1b1f24;--mut:#6b7280;--ok:#16a34a;--warn:#d97706;--bad:#dc2626;--acc:#2563eb;--bd:#e5e7eb}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#181b21;--tx:#e6e8eb;--mut:#9aa3af;--bd:#262a32;--acc:#60a5fa}}
*{box-sizing:border-box}body{margin:0;font:14px system-ui,sans-serif;background:var(--bg);color:var(--tx)}
header{display:flex;align-items:center;gap:14px;padding:14px 20px;background:var(--card);border-bottom:1px solid var(--bd);flex-wrap:wrap}
header h1{font-size:17px;margin:0}.mut{color:var(--mut);font-size:12px}
nav{display:flex;gap:4px;padding:8px 20px;overflow-x:auto;background:var(--card);border-bottom:1px solid var(--bd)}
nav button{border:0;background:none;color:var(--mut);padding:8px 14px;border-radius:8px;cursor:pointer;font:inherit;white-space:nowrap}
nav button.on{background:var(--acc);color:#fff}main{max-width:1000px;margin:auto;padding:18px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-bottom:14px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px;margin-bottom:12px}.grid .card{margin:0}
.big{font-size:26px;font-weight:650;margin:2px 0}.bar{height:6px;background:var(--bd);border-radius:4px;margin-top:8px;overflow:hidden}.bar i{display:block;height:100%}
.issue{border-left:4px solid var(--warn);padding:8px 12px;margin:8px 0;background:var(--bg);border-radius:6px;display:flex;gap:10px;justify-content:space-between;align-items:center}
.issue.critical{border-color:var(--bad)}.issue.notice,.issue.info{border-color:var(--acc)}.ok{color:var(--ok)}.bad{color:var(--bad)}
button.a{background:var(--acc);color:#fff;border:0;padding:7px 13px;border-radius:8px;cursor:pointer;font:inherit}button.a.s{background:var(--bd);color:var(--tx)}button.a.d{background:var(--bad)}
table{width:100%;border-collapse:collapse}td,th{padding:6px 4px;text-align:left;border-bottom:1px solid var(--bd)}
input:not([type=checkbox]){width:100%;padding:7px;border:1px solid var(--bd);border-radius:8px;background:var(--bg);color:var(--tx)}
label{display:block;margin:8px 0;text-transform:capitalize;font-size:12px;color:var(--mut)}label input[type=checkbox]{margin-left:8px}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}pre{white-space:pre-wrap;font-size:12px;max-height:340px;overflow:auto;margin:0}
#toast{position:fixed;bottom:18px;right:18px;background:var(--tx);color:var(--bg);padding:10px 16px;border-radius:8px;display:none}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}
</style></head><body>
<header><svg width=54 height=54 viewBox="0 0 100 100"><circle cx=50 cy=50 r=42 fill=none stroke="var(--bd)" stroke-width=10 /><circle id=ring cx=50 cy=50 r=42 fill=none stroke="var(--ok)" stroke-width=10 stroke-linecap=round transform="rotate(-90 50 50)" stroke-dasharray="0 264"/><text id=sc x=50 y=58 text-anchor=middle font-size=26 font-weight=700 fill="currentColor">-</text></svg>
<div><h1 id=host>DeviceWatch</h1><div class=mut id=sub>loading...</div></div></header>
<nav id=nav></nav><main id=main></main><div id=toast></div>
<script>
const TOKEN="__TOKEN__",TABS=['Overview','Hardware','Security','Updates','Processes','Alerts','Settings'];let tab='Overview',S={},H=[],CFG={},LOG='';
const $=id=>document.getElementById(id),col=v=>v>=90?'var(--bad)':v>=75?'var(--warn)':'var(--ok)';
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function toast(t){const e=$('toast');e.textContent=t;e.style.display='block';setTimeout(()=>e.style.display='none',3500)}
async function api(p,body){const o=body?{method:'POST',headers:{'X-Token':TOKEN,'Content-Type':'application/json'},body:JSON.stringify(body)}:{};return (await fetch(p,o)).json()}
async function act(name,arg){const r=await api('/api/action',{name,arg});toast(r.msg||'Done');await load()}
const tile=(n,v,s)=>`<div class=card><div class=mut>${n}</div><div class=big>${v}%</div><div class=mut>${s||''}</div><div class=bar><i style="width:${Math.min(100,v)}%;background:${col(v)}"></i></div></div>`;
const spark=(a,c)=>{if(a.length<2)return'';const p=a.map((v,i)=>`${i*300/(a.length-1)},${60-Math.min(100,v)*.58}`).join(' ');return`<svg viewBox="0 0 300 60" width=100% height=60 preserveAspectRatio=none><polyline fill=none stroke="${c}" stroke-width=2 points="${p}"/></svg>`};
const issueHtml=(x)=>`<div class="issue ${esc(x.severity)}"><div><b>${esc(x.message)}</b><div class=mut>${esc(x.fix)}</div></div>${x.key.startsWith('mal:proc:')?`<button class="a s" onclick="act('ignore','${esc(x.key.slice(9))}')">Ignore</button>`:''}</div>`;
const table=(t,a,k)=>`<div class=card><b>${t}</b><table>${a.map(x=>`<tr><td>${x.name}</td><td>${x[k]}%</td><td><button class="a d" onclick="if(confirm('End ${x.name} (PID ${x.pid})?'))act('kill',${x.pid})">End</button></td></tr>`).join('')}</table></div>`;
const fields=(o,p='')=>Object.entries(o).map(([k,v])=>{const id=p+k;if(v&&typeof v==='object'&&!Array.isArray(v))return`<h4>${k}</h4>`+fields(v,id+'.');
const t=typeof v==='boolean'?`<input type=checkbox data-k="${id}" data-t=b ${v?'checked':''}>`:Array.isArray(v)?`<input data-k="${id}" data-t=a value="${v.join(', ')}">`:`<input data-k="${id}" data-t=${typeof v==='number'?'n':'s'} value="${v}" ${/password|key/.test(id)?'type=password':''}>`;return`<label>${k.replace(/_/g,' ')}${t}</label>`}).join('');
async function save(){const o={};document.querySelectorAll('[data-k]').forEach(e=>{let v=e.dataset.t==='b'?e.checked:e.dataset.t==='n'?Number(e.value):e.dataset.t==='a'?e.value.split(',').map(s=>s.trim()).filter(Boolean):e.value;let r=o,ks=e.dataset.k.split('.');ks.slice(0,-1).forEach(k=>r=r[k]=r[k]||{});r[ks.pop()]=v});const r=await api('/api/config',o);toast(r.msg);CFG=await api('/api/config')}
function view(){const m=S.metrics||{},sc=m.security||{},u=m.updates||{},is=S.issues||[];let h='';
if(tab==='Overview'){h+='<div class=grid>'+tile('CPU',m.cpu_percent,m.cpu_cores+' cores')+tile('Memory',m.ram_percent,m.ram_used_gb+' / '+m.ram_total_gb+' GB');(m.disks||[]).forEach(d=>h+=tile('Disk '+d.mount,d.percent,d.free_gb+' GB free'));
if(m.battery_percent!=null)h+=tile('Battery',m.battery_percent,m.battery_plugged?'charging':'on battery');if(m.battery_health_percent!=null)h+=tile('Battery health',m.battery_health_percent,(m.battery_health_label||'')+' | '+m.battery_wear_percent+'% wear'+(m.battery_cycle_count!=null?' | '+m.battery_cycle_count+' cycles':''));if(m.max_temp_c!=null)h+=tile('Temperature',m.max_temp_c,m.max_temp_c+' C');
h+=`<div class=card><div class=mut>Network</div><div class=big>${m.network_ok?'<span class=ok>Online</span>':'<span class=bad>Offline</span>'}</div><div class=mut>${m.network_latency_ms==null?'latency unavailable':m.network_latency_ms+' ms average'} | ${m.network_loss_percent||0}% probe loss</div><div class=mut>uptime ${m.uptime_days} d</div></div>`;
h+=`<div class=card><div class=mut>Protection</div><div class=big>${sc.av_ok===false?'<span class=bad>At risk</span>':sc.last_scan?'<span class=ok>OK</span>':'...'}</div><div class=mut>${sc.summary||'scanning...'}</div></div>`;
h+=`<div class=card><div class=mut>Updates</div><div class=big>${u.checked?u.count:'...'}</div><div class=mut>${u.checked?u.security+' security':'checking...'}</div></div></div>`;
h+=`<div class=cols><div class=card><b>CPU history</b>${spark(H.map(x=>x.cpu),'var(--acc)')}</div><div class=card><b>Memory history</b>${spark(H.map(x=>x.ram),'var(--warn)')}</div><div class=card><b>Health score</b>${spark(H.map(x=>x.score),'var(--ok)')}</div><div class=card><b>Battery history</b>${spark(H.filter(x=>x.battery!=null).map(x=>x.battery),'var(--ok)')}</div><div class=card><b>Battery health trend</b>${spark(H.filter(x=>x.battery_health!=null).map(x=>x.battery_health),'var(--warn)')}</div></div>`;
h+='<div class=card><b>Current issues</b>'+(is.length?is.map(issueHtml).join(''):'<div class=ok>No problems detected.</div>')+'</div>'}
if(tab==='Hardware'){const dh=m.disk_health||{},th=m,bs=m.backups||[];h+=`<div class=card><b>Drive health</b><p><button class=a onclick="act('hardware')">Check hardware and backups</button></p>`;
h+=dh.available?'<table><tr><th>Drive</th><th>Status</th><th>Temperature</th><th>Details</th></tr>'+dh.devices.map(d=>`<tr><td>${esc(d.name)}</td><td class=${d.healthy===true?'ok':d.healthy===false?'bad':''}>${esc(d.status)}</td><td>${d.temperature_c==null?'n/a':esc(d.temperature_c)+' C'}</td><td>${esc((d.problems||[]).join('; '))}</td></tr>`).join('')+'</table>':`<div class=mut>${esc(dh.note||'SMART scan has not completed or is unavailable.')}</div>`;h+='</div>';
h+='<div class=card><b>Backups</b>'+(bs.length?'<table><tr><th>Path</th><th>Last backup</th><th>Age</th><th>Status</th></tr>'+bs.map(b=>`<tr><td>${esc(b.path)}</td><td>${esc(b.last_backup||'not found')}</td><td>${b.age_days==null?'n/a':esc(b.age_days)+' days'}</td><td class=${b.fresh?'ok':'bad'}>${b.fresh?'Fresh':'Stale or missing'}</td></tr>`).join('')+'</table>':'<div class=mut>Set backup_paths in Settings to monitor backup files or folders.</div>')+'</div>';
h+='<div class=card><b>Cooling and throttling</b><div class=mut>'+(th.throttle_count==null?'CPU throttle counter unavailable':'Thermal throttle events: '+esc(th.throttle_count))+(th.cpu_speed_limit_percent==null?'':' | CPU speed limit: '+esc(th.cpu_speed_limit_percent)+'%')+'</div>'+(th.fan_speeds&&th.fan_speeds.length?'<table><tr><th>Fan</th><th>Speed</th></tr>'+th.fan_speeds.map(f=>`<tr><td>${esc(f.name)}</td><td>${f.rpm==null?'n/a':esc(f.rpm)+' RPM'}</td></tr>`).join('')+'</table>':'<div class=mut>Fan speed sensors unavailable on this device.</div>')+'</div>'}
if(tab==='Security'){const sf=is.filter(x=>x.key.startsWith('mal:'));h+=`<div class=card><b>Protection status</b><p>${sc.summary||'Scan has not finished yet.'}</p><div class=mut>Last scan: ${sc.last_scan||'-'}</div><p><button class=a onclick="act('scan')">Scan now</button></p></div>`;
h+='<div class=card><b>Findings</b>'+(sf.length?sf.map(issueHtml).join(''):'<div class=ok>Nothing suspicious found.</div>')+'</div>';
h+=`<div class=card><b>Hash blocklist</b><div class=mut>Paste a SHA-256 of a known-bad file; any running program matching it is flagged critical.</div><div class=row><input id=bh placeholder="64-character SHA-256"><button class=a onclick="act('blocklist',$('bh').value)">Add</button></div></div>`;
h+=`<div class=card><b>Ignored processes</b><p class=mut>${(CFG.ignore_process_names||[]).join(', ')||'none (edit under Settings)'}</p></div>`}
if(tab==='Updates'){h+=`<div class=card><div class=big>${u.checked?u.count+' pending':'Checking...'}</div><div class=mut>${u.security||0} security - ${u.reboot?'<b>restart required</b>':'no restart needed'} - last check ${u.checked||'-'}</div>${u.error?'<p class=bad>'+esc(u.error)+'</p>':''}<p><button class=a onclick="act('updates')">Check now</button></p></div>`;
h+='<div class=card><b>Available OS updates</b>'+((u.titles||[]).length?'<table>'+u.titles.map(t=>`<tr><td>${esc(t)}</td></tr>`).join('')+'</table>':'<p class=ok>None reported.</p>')+'</div>';
const au=m.app_updates||{};h+='<div class=card><b>Application updates</b><div class=mut>'+(!au.available?'Supported package manager unavailable':au.count+' update(s) found')+'</div>'+(au.apps&&au.apps.length?'<table><tr><th>Application</th><th>Installed</th><th>Available</th></tr>'+au.apps.map(a=>`<tr><td>${esc(a.name||a.id)}</td><td>${esc(a.current||'unknown')}</td><td>${esc(a.latest||'unknown')}</td></tr>`).join('')+'</table>':'')+'</div>'}
if(tab==='Processes')h+='<div class=cols>'+table('Top CPU',m.top_cpu||[],'cpu')+table('Top memory',m.top_mem||[],'mem')+'</div>';
if(tab==='Alerts'){h+=`<div class=card><b>Active alerts</b>${is.length?is.map(issueHtml).join(''):'<div class=ok>All clear.</div>'}<p><button class="a s" onclick="act('test')">Send test notification</button></p></div><div class=card><b>Log</b><pre>${LOG||'(empty)'}</pre></div>`}
if(tab==='Settings'){h+=`<div class=card><b>Settings</b><div class=mut>Saved to config file. Interval and port changes apply after restart.</div>${fields(CFG)}<p class=row><button class=a onclick="save()">Save settings</button><button class="a s" onclick="if(confirm('Delete temp files older than 7 days?'))act('clean')">Clean old temp files</button></p></div>`}
return h}
let editing=false;function draw(){const m=S.metrics||{};if(m.time){$('host').textContent=m.host;$('sub').textContent=m.os+' - updated '+m.time;$('sc').textContent=S.score;const r=$('ring');r.setAttribute('stroke-dasharray',S.score*2.64+' 264');r.setAttribute('stroke',S.score>=80?'var(--ok)':S.score>=50?'var(--warn)':'var(--bad)')}
$('nav').innerHTML=TABS.map(t=>`<button class="${t===tab?'on':''}" onclick="tab='${t}';load(true)">${t}</button>`).join('');if(!(tab==='Settings'&&editing))$('main').innerHTML=view()}
async function load(force){try{S=await api('/api/status');if(tab==='Overview')H=await api('/api/history');if(tab==='Alerts')LOG=(await api('/api/log')).log;if(tab==='Settings'&&(force||!Object.keys(CFG).length)){CFG=await api('/api/config');editing=false}else if(!CFG.interval_seconds)CFG=await api('/api/config');draw();if(tab==='Settings')editing=true}catch(e){}}
load(true);setInterval(()=>load(),5000);
</script></body></html>"""


def do_action(mon, name, arg):
    try:
        if name == "scan":
            mon.security_scan()
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
        if name == "clean":
            return {"msg": f"Freed {mon.auto_fix_disk()} MB of old temp files"}
        if name == "test":
            mon.notify_desktop("DeviceWatch", "Test notification - alerts are working.")
            mon.send_webhook("DeviceWatch test alert")
            return {"msg": "Test alert sent"}
        if name == "ignore":
            names = mon.cfg["ignore_process_names"]
            if arg not in names:
                names.append(arg)
            CONFIG_PATH.write_text(json.dumps(mon.cfg, indent=2))
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
            p = psutil.Process(int(arg))
            nm = p.name()
            p.terminate()
            return {"msg": f"Ended {nm}"}
    except Exception as e:
        return {"msg": f"Failed: {e}"}
    return {"msg": "Unknown action"}


def start_dashboard(mon, port):
    token = secrets.token_hex(16)
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}   # blocks DNS-rebinding attacks

    class H(BaseHTTPRequestHandler):
        def send(self, obj, code=200, ctype="application/json"):
            body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.headers.get("Host") not in hosts:
                return self.send({"error": "forbidden"}, 403)
            path = self.path.split("?")[0]
            if path == "/api/status":
                self.send(mon.latest)
            elif path == "/api/history":
                try:
                    rows = [json.loads(l) for l in HISTORY_PATH.read_text().splitlines()[-120:]]
                except Exception:
                    rows = []
                self.send(rows)
            elif path == "/api/log":
                try:
                    self.send({"log": "\n".join(LOG_PATH.read_text().splitlines()[-80:])})
                except Exception:
                    self.send({"log": ""})
            elif path == "/api/config":
                self.send(mon.cfg)
            else:
                self.send(PAGE.replace("__TOKEN__", token).encode(), 200, "text/html; charset=utf-8")

        def do_POST(self):
            if self.headers.get("Host") not in hosts or self.headers.get("X-Token") != token:
                return self.send({"msg": "Forbidden"}, 403)
            try:
                data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            except ValueError:
                return self.send({"msg": "Bad request"}, 400)
            if self.path == "/api/action":
                return self.send(do_action(mon, data.get("name"), data.get("arg")))
            if self.path == "/api/config":
                for k, v in data.items():
                    if k in mon.cfg and isinstance(mon.cfg[k], dict) and isinstance(v, dict):
                        mon.cfg[k].update(v)
                    elif k in mon.cfg:
                        mon.cfg[k] = v
                CONFIG_PATH.write_text(json.dumps(mon.cfg, indent=2))
                return self.send({"msg": "Settings saved"})
            self.send({"msg": "Not found"}, 404)

        def log_message(self, *a):
            pass

    try:
        srv = ThreadingHTTPServer(("127.0.0.1", port), H)  # localhost only
    except OSError as e:
        print(f"Dashboard not started on port {port}: {e}")
        return None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"Interface: http://127.0.0.1:{port}")
    return f"http://127.0.0.1:{port}"


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
    network_detail = "latency unavailable" if m.get("network_latency_ms") is None else f"{m['network_latency_ms']} ms, {m['network_loss_percent']}% probe loss"
    print(f"Network: {'online' if m['network_ok'] else 'OFFLINE'} ({network_detail})")
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


def main():
    ap = argparse.ArgumentParser(description="DeviceWatch - device health monitor")
    ap.add_argument("--once", action="store_true", help="run one check, print a report, exit")
    ap.add_argument("--init", action="store_true", help="write a default config file and exit")
    ap.add_argument("--no-dashboard", action="store_true")
    ap.add_argument("--no-browser", action="store_true", help="don't open the dashboard in your browser")
    args = ap.parse_args()

    HOME.mkdir(exist_ok=True)
    if args.init:
        if not CONFIG_PATH.exists():
            CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
        print(f"Edit your settings in: {CONFIG_PATH}")
        return

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()])
    cfg = load_config()
    mon = Monitor(cfg)

    if args.once:
        print("Running health, security, hardware, backup, and update checks (some may take a few minutes)...")
        mon.security_scan()
        mon.update_scan()
        mon.disk_health_scan()
        mon.app_update_scan()
        mon.backup_scan()
        print_report(mon.tick())
        return

    dashboard_url = None
    if not args.no_dashboard:
        dashboard_url = start_dashboard(mon, cfg["dashboard_port"])
    mon.start_background()
    if dashboard_url and not args.no_browser:
        try:
            mon.tick()  # take one reading first so the page isn't blank on load
        except Exception:
            logging.exception("First check failed")
        webbrowser.open(dashboard_url)
    logging.info("DeviceWatch started (checking every %ss). Ctrl+C to stop.", cfg["interval_seconds"])
    try:
        while True:
            try:
                res = mon.tick()
                logging.info("score=%s cpu=%s%% ram=%s%% issues=%d", res["score"],
                             res["metrics"]["cpu_percent"], res["metrics"]["ram_percent"], len(res["issues"]))
            except Exception:
                logging.exception("Check failed")
            time.sleep(cfg["interval_seconds"])
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()