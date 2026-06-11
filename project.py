"""
wifi_detector_windows.py — Enhanced Evil Twin / Rogue AP Detector
with K-Means Clustering for anomaly detection
"""

import subprocess
import json
import re
import time
import sys
import pickle
import numpy as np
from collections import defaultdict
from datetime import datetime

class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def enable_ansi_windows():
    if sys.platform == "win32":
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)

OUI_DB = {
    "00:50:F2": "Microsoft",       "00:0C:E7": "Cisco",
    "00:1A:2B": "Cisco",           "F8:1A:67": "TP-Link",
    "EC:08:6B": "TP-Link",         "50:C7:BF": "TP-Link",
    "B0:BE:76": "TP-Link",         "C4:E9:84": "TP-Link",
    "18:D6:C7": "TP-Link",         "54:AF:97": "TP-Link",
    "00:1E:E5": "Netgear",         "C0:FF:D4": "Netgear",
    "A0:40:A0": "Netgear",         "28:80:88": "Netgear",
    "9C:3D:CF": "Netgear",         "20:E5:2A": "Belkin",
    "94:10:3E": "Belkin",          "EC:1A:59": "Belkin",
    "00:26:B9": "Dell",            "F8:DB:88": "Dell",
    "3C:97:0E": "Huawei",          "54:89:98": "Huawei",
    "00:E0:FC": "Huawei",          "C8:94:BB": "Huawei",
    "00:25:9C": "Cisco",           "00:1B:8F": "D-Link",
    "1C:7E:E5": "D-Link",          "00:0D:88": "D-Link",
    "B8:A3:86": "D-Link",          "F0:7D:68": "D-Link",
    "00:24:01": "ASUS",            "04:D9:F5": "ASUS",
    "74:D0:2B": "ASUS",            "AC:22:0B": "ASUS",
    "2C:FD:A1": "ASUS",            "00:17:C5": "ZyXEL",
    "00:13:49": "ZyXEL",           "00:90:4C": "Epigram (Broadcom)",
    "00:17:F2": "Apple",           "3C:15:C2": "Apple",
    "A4:C3:F0": "Apple",           "F4:F1:5A": "Apple",
    "60:F8:1D": "Samsung",         "78:52:1A": "Samsung",
    "F4:7B:5E": "Samsung",         "08:55:31": "Samsung",
    "00:16:EA": "Intel",           "00:1F:3B": "Intel",
    "8C:EC:4B": "Intel",           "34:E6:D7": "Intel",
    "00:08:CA": "Ralink",          "00:0C:43": "Ralink",
    "00:1C:BF": "Atheros",         "00:03:7F": "Atheros",
    "40:A3:6B": "Linksys",         "00:14:BF": "Linksys",
    "00:1A:70": "Linksys",         "58:6D:8F": "Linksys",
    "00:26:18": "Linksys",         "F0:9F:C2": "Ubiquiti",
    "04:18:D6": "Ubiquiti",        "80:2A:A8": "Ubiquiti",
    "00:15:6D": "Ubiquiti",        "24:A4:3C": "MikroTik",
    "B8:69:F4": "MikroTik",        "CC:2D:E0": "MikroTik",
    "DC:9F:DB": "MikroTik",
}

# ── Load K-Means model ────────────────────────────────────────────────────────
try:
    kmeans_model      = pickle.load(open("kmeans_model.pkl",     "rb"))
    kmeans_scaler     = pickle.load(open("scaler.pkl",           "rb"))
    malicious_cluster = pickle.load(open("malicious_cluster.pkl","rb"))
    KMEANS_READY = True
except FileNotFoundError:
    KMEANS_READY = False

def get_vendor(bssid: str) -> str:
    oui = bssid.upper()[:8]
    return OUI_DB.get(oui, "Unknown Vendor")

def is_randomized_mac(bssid: str) -> bool:
    try:
        first_octet = int(bssid.replace(":", "").replace("-", "")[:2], 16)
        return bool(first_octet & 0x02)
    except:
        return False

def get_band(radio: str) -> str:
    r = radio.lower()
    if "802.11ax" in r or "802.11ac" in r or "5" in r:
        return "5GHz"
    elif "802.11n" in r or "802.11g" in r or "802.11b" in r or "2.4" in r:
        return "2.4GHz"
    return "Unknown"

def encode_auth(auth: str) -> int:
    auth = auth.lower()
    if "open" in auth or auth == "":  return 0
    if "wpa3" in auth:                return 3
    if "wpa2" in auth:                return 2
    if "wpa"  in auth:                return 1
    if "wep"  in auth:                return 4
    return 0

def kmeans_predict(net: dict) -> tuple[str, float]:
    """Predict Safe/Malicious using K-Means cluster distance."""
    if not KMEANS_READY:
        return "N/A", 0.0
    try:
        signal_pct = int(net.get("signal", "0%").replace("%", ""))
    except:
        signal_pct = 0

    features = np.array([[
        signal_pct,
        encode_auth(net.get("authentication", "")),
        1 if net.get("duplicate_ssid")              else 0,
        1 if net.get("randomized_mac")              else 0,
        1 if net.get("network_type","").lower() == "adhoc" else 0,
        1 if signal_pct >= 90                       else 0,
    ]])

    features_scaled = kmeans_scaler.transform(features)
    cluster         = kmeans_model.predict(features_scaled)[0]

    # Distance to both cluster centers — closer = more confident
    distances       = kmeans_model.transform(features_scaled)[0]
    dist_malicious  = distances[malicious_cluster]
    dist_safe       = distances[1 - malicious_cluster]
    total           = dist_malicious + dist_safe
    confidence      = (1 - dist_malicious / total) * 100 if cluster == malicious_cluster else (1 - dist_safe / total) * 100

    label = "Malicious" if cluster == malicious_cluster else "Safe"
    return label, round(confidence, 1)

def safety_advice(net: dict) -> str:
    auth  = net.get("authentication", "").lower()
    enc   = net.get("encryption", "").lower()
    score = net.get("risk_score", 0)
    if "open" in auth or "none" in enc:
        return "⛔ Do NOT connect — all traffic visible to anyone nearby"
    if "wep" in enc:
        return "⛔ Do NOT connect — WEP is broken and easily decrypted"
    if net.get("duplicate_ssid"):
        return "⚠  Verify with network owner before connecting — possible evil twin"
    if net.get("randomized_mac"):
        return "⚠  MAC appears spoofed — treat with caution"
    if score >= 30:
        return "⚠  Avoid connecting until source is verified"
    return "✔  Appears safe but always use a VPN on public networks"

def signal_bar(signal_str: str) -> str:
    try:
        pct = int(signal_str.replace("%", "").strip())
    except ValueError:
        return "????"
    filled = round(pct / 10)
    bar = "█" * filled + "░" * (10 - filled)
    if pct >= 75:   color = C.GREEN
    elif pct >= 40: color = C.YELLOW
    else:           color = C.RED
    return f"{color}{bar}{C.RESET} {pct:>3}%"

def risk_score(net: dict) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    auth = net.get("authentication", "").lower()
    enc  = net.get("encryption", "").lower()

    if "open" in auth or "none" in enc:
        score += 40
        reasons.append("Open network — no encryption")
    elif "wep" in enc:
        score += 35
        reasons.append("WEP encryption — easily cracked")
    elif "wpa2" not in auth and "wpa3" not in auth:
        score += 15
        reasons.append("Weak/unknown authentication")

    if net.get("duplicate_ssid"):
        score += 35
        reasons.append("SSID shared by multiple BSSIDs (evil twin risk)")

    try:
        pct = int(net.get("signal", "0%").replace("%", ""))
        if pct >= 90:
            score += 10
            reasons.append("Unusually strong signal — may be a rogue AP nearby")
    except ValueError:
        pass

    if net.get("randomized_mac"):
        score += 20
        reasons.append("Randomized/spoofed MAC address detected")

    if net.get("network_type", "").lower() == "adhoc":
        score += 30
        reasons.append("Ad-hoc (peer-to-peer) network — highly suspicious")

    if net.get("vendor", "Unknown Vendor") == "Unknown Vendor":
        score += 5
        reasons.append("Unrecognized hardware vendor")

    return min(score, 100), reasons

def risk_label(score: int) -> str:
    if score >= 60:   return f"{C.RED}{C.BOLD}HIGH  {C.RESET}"
    elif score >= 30: return f"{C.YELLOW}MEDIUM{C.RESET}"
    else:             return f"{C.GREEN}LOW   {C.RESET}"

# ── Core scanner ──────────────────────────────────────────────────────────────

def _make_net(ssid, bssid, signal="50%", radio="", channel="",
              network_type="Infrastructure", auth="WPA2-Personal", enc="CCMP"):
    return {
        "ssid": ssid or "<Hidden>",
        "bssid": bssid,
        "vendor": get_vendor(bssid),
        "randomized_mac": is_randomized_mac(bssid),
        "signal": signal,
        "radio": radio,
        "channel": channel,
        "network_type": network_type,
        "authentication": auth,
        "encryption": enc,
        "duplicate_ssid": False,
    }

def _finalize_networks(networks: list[dict]) -> list[dict]:
    """Mark duplicate SSIDs and compute risk scores."""
    networks = [n for n in networks if n.get("ssid") and n.get("bssid")]
    ssid_counts = defaultdict(int)
    for n in networks:
        ssid_counts[n["ssid"]] += 1
    for n in networks:
        if ssid_counts[n["ssid"]] > 1:
            n["duplicate_ssid"] = True
    for n in networks:
        n["risk_score"], n["risk_reasons"] = risk_score(n)
    return sorted(networks, key=lambda x: x["risk_score"], reverse=True)

def _scan_windows() -> list[dict]:
    raw = subprocess.check_output(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        shell=True, stderr=subprocess.DEVNULL
    ).decode(errors="ignore")

    networks = []
    current_ssid = None
    current_net  = {}

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if re.match(r"^SSID\s+\d+\s*:", line):
            current_ssid = line.split(":", 1)[1].strip()
        elif line.lower().startswith("bssid"):
            if current_net:
                networks.append(current_net)
            bssid_match = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
            bssid = bssid_match.group(1) if bssid_match else line.split(":", 1)[1].strip()
            current_net = _make_net(current_ssid, bssid)
        elif line.lower().startswith("signal") and current_net:
            current_net["signal"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("radio type") and current_net:
            current_net["radio"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("channel") and current_net:
            current_net["channel"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("network type") and current_net:
            current_net["network_type"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("authentication") and current_net:
            current_net["authentication"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("encryption") and current_net:
            current_net["encryption"] = line.split(":", 1)[1].strip()

    if current_net and "ssid" in current_net:
        networks.append(current_net)
    return networks

def _scan_linux() -> list[dict]:
    """Parse iwlist output on Linux."""
    import shutil
    iface = None
    # Try to detect wireless interface
    try:
        iw_out = subprocess.check_output(
            ["iw", "dev"], stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
        for ln in iw_out.splitlines():
            if "Interface" in ln:
                iface = ln.strip().split()[-1]
                break
    except Exception:
        pass

    if not iface:
        # Fall back to first wlan* interface from /proc/net/wireless
        try:
            with open("/proc/net/wireless") as f:
                for ln in f.readlines()[2:]:
                    iface = ln.split(":")[0].strip()
                    if iface:
                        break
        except Exception:
            pass

    if not iface:
        raise RuntimeError("No wireless interface found")

    raw = subprocess.check_output(
        ["sudo", "iwlist", iface, "scan"],
        stderr=subprocess.DEVNULL
    ).decode(errors="ignore")

    networks = []
    current_net = {}

    def dbm_to_pct(dbm_str):
        """Convert dBm to rough percentage."""
        try:
            dbm = float(re.search(r"[-\d.]+", dbm_str).group())
            pct = max(0, min(100, int(2 * (dbm + 100))))
            return f"{pct}%"
        except Exception:
            return "50%"

    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("Cell "):
            if current_net:
                networks.append(current_net)
            bssid_match = re.search(r"Address:\s*([0-9A-Fa-f:]{17})", line)
            bssid = bssid_match.group(1) if bssid_match else "00:00:00:00:00:00"
            current_net = _make_net(None, bssid)
        elif "ESSID:" in line and current_net:
            ssid = re.search(r'ESSID:"(.*?)"', line)
            current_net["ssid"] = ssid.group(1) if ssid else "<Hidden>"
            current_net["vendor"] = get_vendor(current_net["bssid"])
        elif re.search(r"Signal level", line) and current_net:
            sig_match = re.search(r"Signal level[=:](.+?)(\s|$)", line)
            if sig_match:
                current_net["signal"] = dbm_to_pct(sig_match.group(1))
        elif "Channel:" in line and current_net:
            ch = re.search(r"Channel:(\d+)", line)
            if ch:
                current_net["channel"] = ch.group(1)
        elif "Encryption key:" in line and current_net:
            if "off" in line.lower():
                current_net["authentication"] = "Open"
                current_net["encryption"] = "None"
        elif "IE: IEEE 802.11i/WPA2" in line and current_net:
            current_net["authentication"] = "WPA2-Personal"
            current_net["encryption"] = "CCMP"
        elif "IE: WPA Version" in line and current_net:
            if "WPA2" not in current_net.get("authentication", ""):
                current_net["authentication"] = "WPA-Personal"
                current_net["encryption"] = "TKIP"
        elif "Mode:" in line and current_net:
            mode_match = re.search(r"Mode:(\S+)", line)
            if mode_match:
                mode = mode_match.group(1)
                current_net["network_type"] = "Ad-Hoc" if mode.lower() == "ad-hoc" else "Infrastructure"

    if current_net and current_net.get("bssid"):
        networks.append(current_net)
    return networks

def _scan_macos() -> list[dict]:
    """Parse airport output on macOS."""
    airport_paths = [
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
        "/usr/sbin/airport",
    ]
    airport = next((p for p in airport_paths if __import__("os").path.exists(p)), None)
    if not airport:
        raise RuntimeError("airport utility not found")

    raw = subprocess.check_output(
        [airport, "-s"], stderr=subprocess.DEVNULL
    ).decode(errors="ignore")

    networks = []
    for line in raw.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            # Format: SSID  BSSID  RSSI  CHANNEL  HT  CC  SECURITY
            # SSID may have spaces; BSSID is xx:xx:xx:xx:xx:xx
            bssid_match = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
            if not bssid_match:
                continue
            bssid = bssid_match.group(1)
            bssid_start = line.index(bssid)
            ssid = line[:bssid_start].strip()
            rest = line[bssid_start + len(bssid):].split()
            rssi = int(rest[0]) if rest else -70
            channel = rest[1] if len(rest) > 1 else ""
            security = " ".join(rest[3:]) if len(rest) > 3 else "WPA2"
            pct = max(0, min(100, int(2 * (rssi + 100))))
            auth = "Open" if "NONE" in security.upper() else ("WPA2-Personal" if "WPA2" in security.upper() else "WPA-Personal")
            enc  = "None" if auth == "Open" else "CCMP"
            net = _make_net(ssid, bssid, signal=f"{pct}%",
                            channel=str(channel), auth=auth, enc=enc)
            networks.append(net)
        except Exception:
            continue
    return networks

def _scan_demo() -> list[dict]:
    """Return synthetic networks when no real scanner is available (demo/offline mode)."""
    print(f"{C.YELLOW}⚠  No Wi-Fi scanner available — running in DEMO mode with synthetic data.{C.RESET}\n")
    demo = [
        _make_net("HomeNetwork",      "F8:1A:67:AA:BB:CC", "72%",  "802.11n",  "6",  "Infrastructure", "WPA2-Personal",  "CCMP"),
        _make_net("CoffeeShop_Free",  "00:00:00:DE:AD:01", "88%",  "802.11ac", "11", "Infrastructure", "Open",           "None"),
        _make_net("HomeNetwork",      "CA:FE:BA:BE:00:01", "91%",  "802.11ac", "6",  "Infrastructure", "WPA2-Personal",  "CCMP"),  # evil twin
        _make_net("NETGEAR_ROGUE",    "02:AB:CD:EF:12:34", "95%",  "802.11ac", "1",  "Infrastructure", "Open",           "None"),
        _make_net("CorpWifi",         "00:25:9C:11:22:33", "55%",  "802.11ac", "36", "Infrastructure", "WPA2-Enterprise","CCMP"),
        _make_net("OldRouter",        "00:1B:8F:44:55:66", "30%",  "802.11b",  "11", "Infrastructure", "WEP",            "WEP"),
        _make_net("AdhocNet",         "02:FF:AA:BB:CC:DD", "80%",  "802.11n",  "6",  "Ad-Hoc",         "Open",           "None"),
    ]
    return demo

def scan_wifi() -> list[dict]:
    """Scan Wi-Fi networks — Windows, Linux, macOS, or demo fallback."""
    networks = []
    platform = sys.platform

    if platform == "win32":
        try:
            networks = _scan_windows()
        except subprocess.CalledProcessError:
            print(f"{C.RED}Error: Could not run netsh. Try running as Administrator.{C.RESET}")
            sys.exit(1)
    elif platform.startswith("linux"):
        try:
            networks = _scan_linux()
        except Exception as e:
            print(f"{C.YELLOW}⚠  Linux scan failed ({e}). Falling back to demo mode.{C.RESET}")
            networks = _scan_demo()
    elif platform == "darwin":
        try:
            networks = _scan_macos()
        except Exception as e:
            print(f"{C.YELLOW}⚠  macOS scan failed ({e}). Falling back to demo mode.{C.RESET}")
            networks = _scan_demo()
    else:
        networks = _scan_demo()

    if not networks:
        print(f"{C.YELLOW}⚠  Scanner returned no results — running in demo mode.{C.RESET}")
        networks = _scan_demo()

    return _finalize_networks(networks)

# ── Display ───────────────────────────────────────────────────────────────────
def print_header():
    km_status = f"{C.GREEN}✔ K-Means Active{C.RESET}" if KMEANS_READY else f"{C.RED}✘ K-Means Not Loaded{C.RESET}"
    print(f"\n{C.CYAN}{C.BOLD}{'═'*70}")
    print(f"   🛡  Wi-Fi Security Analyzer  •  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   🤖  ML Model: {km_status}")
    print(f"{'═'*70}{C.RESET}\n")

def print_network_table(networks: list[dict]):
    print(f"{C.BOLD}{'SSID':<28} {'BSSID':<19} {'SIGNAL':>14}  {'AUTH':<16} {'RISK':<8}{C.RESET}")
    print("─" * 90)
    for n in networks:
        ssid_display = (n['ssid'][:26] + "..") if len(n['ssid']) > 28 else n['ssid']
        auth_short   = n['authentication'][:14]
        print(
            f"{ssid_display:<28} "
            f"{C.DIM}{n['bssid']:<19}{C.RESET} "
            f"{signal_bar(n['signal'])}  "
            f"{auth_short:<16} "
            f"{risk_label(n['risk_score'])}"
        )

def print_threat_report(networks: list[dict]):
    threats = [n for n in networks if n["risk_score"] > 0]
    if not threats:
        print(f"\n{C.GREEN}✔  No significant threats detected.{C.RESET}\n")
        return

    print(f"\n{C.RED}{C.BOLD}⚠  THREAT REPORT  ({len(threats)} network(s) flagged){C.RESET}")
    print("─" * 70)
    for n in threats:
        score    = n["risk_score"]
        band     = get_band(n.get("radio", ""))
        mac_flag = f"{C.RED} [RANDOMIZED MAC]{C.RESET}" if n.get("randomized_mac") else ""

        print(f"\n  {C.BOLD}{n['ssid']}{C.RESET}  [{n['bssid']}]{mac_flag}")
        print(f"  {'─'*60}")
        print(f"  {'Vendor':<20}: {n['vendor']}")
        print(f"  {'Risk Score':<20}: {risk_label(score)} ({score}/100)")
        print(f"  {'Signal':<20}: {n['signal']}")
        print(f"  {'Authentication':<20}: {n['authentication'] or 'Unknown'}")
        print(f"  {'Encryption':<20}: {n['encryption'] or 'Unknown'}")
        print(f"  {'Band':<20}: {band}")
        print(f"  {'Channel':<20}: {n['channel'] or 'Unknown'}")
        print(f"  {'Network Type':<20}: {n['network_type'] or 'Unknown'}")
        print(f"  {'Radio Type':<20}: {n['radio'] or 'Unknown'}")
        print(f"  {'Duplicate SSID':<20}: {'Yes ⚠' if n['duplicate_ssid'] else 'No'}")

        print(f"\n  {C.BOLD}Issues:{C.RESET}")
        for r in n["risk_reasons"]:
            print(f"    {C.RED}→ {r}{C.RESET}")

        # K-Means prediction
        label, confidence = kmeans_predict(n)
        if label == "Malicious":
            km_color = C.RED
        elif label == "Safe":
            km_color = C.GREEN
        else:
            km_color = C.DIM
        print(f"\n  {C.BOLD}{'K-Means Prediction':<20}{C.RESET}: {km_color}{C.BOLD}{label}{C.RESET} ({confidence}% confidence)")

        advice = safety_advice(n)
        print(f"  {C.CYAN}Advice: {advice}{C.RESET}")
        print(f"  {'─'*60}")

def print_statistics(networks: list[dict]):
    total     = len(networks)
    open_ap   = sum(1 for n in networks if "open" in n["authentication"].lower())
    wep_ap    = sum(1 for n in networks if "wep"  in n["encryption"].lower())
    high      = sum(1 for n in networks if n["risk_score"] >= 60)
    medium    = sum(1 for n in networks if 30 <= n["risk_score"] < 60)
    low       = sum(1 for n in networks if 0 < n["risk_score"] < 30)
    dup_ssids = len({n["ssid"] for n in networks if n["duplicate_ssid"]})
    rand_macs = sum(1 for n in networks if n.get("randomized_mac"))

    # K-Means counts
    if KMEANS_READY:
        ml_malicious = sum(1 for n in networks if kmeans_predict(n)[0] == "Malicious")
        ml_safe      = total - ml_malicious
    else:
        ml_malicious = ml_safe = 0

    print(f"\n{C.BOLD}── Summary ──────────────────────────────{C.RESET}")
    print(f"  Total networks       : {total}")
    print(f"  Open (no auth)       : {C.RED}{open_ap}{C.RESET}")
    print(f"  WEP (weak enc)       : {C.RED}{wep_ap}{C.RESET}")
    print(f"  Duplicate SSIDs      : {C.YELLOW}{dup_ssids}{C.RESET}")
    print(f"  Randomized MACs      : {C.YELLOW}{rand_macs}{C.RESET}")
    print(f"  High risk            : {C.RED}{high}{C.RESET}")
    print(f"  Medium risk          : {C.YELLOW}{medium}{C.RESET}")
    print(f"  Low risk             : {C.GREEN}{low}{C.RESET}")
    if KMEANS_READY:
        print(f"  K-Means Malicious    : {C.RED}{ml_malicious}{C.RESET}")
        print(f"  K-Means Safe         : {C.GREEN}{ml_safe}{C.RESET}")

def export_report(networks: list[dict], fmt: str = "txt"):
    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"wifi_report_{ts}.{fmt}"

    if fmt == "json":
        safe = [{k: v for k, v in n.items() if k != "risk_reasons"} for n in networks]
        for i, n in enumerate(networks):
            safe[i]["risk_reasons"]     = n["risk_reasons"]
            lbl, conf                   = kmeans_predict(n)
            safe[i]["kmeans_prediction"] = lbl
            safe[i]["kmeans_confidence"] = conf
        with open(fname, "w") as f:
            json.dump(safe, f, indent=2)
    else:
        with open(fname, "w") as f:
            f.write(f"Wi-Fi Security Report — {datetime.now()}\n")
            f.write("=" * 70 + "\n\n")
            for n in networks:
                band      = get_band(n.get("radio", ""))
                lbl, conf = kmeans_predict(n)
                f.write(f"SSID              : {n['ssid']}\n")
                f.write(f"BSSID             : {n['bssid']}\n")
                f.write(f"Vendor            : {n['vendor']}\n")
                f.write(f"Randomized MAC    : {'Yes' if n.get('randomized_mac') else 'No'}\n")
                f.write(f"Signal            : {n['signal']}\n")
                f.write(f"Band              : {band}\n")
                f.write(f"Channel           : {n['channel'] or 'Unknown'}\n")
                f.write(f"Network Type      : {n['network_type'] or 'Unknown'}\n")
                f.write(f"Radio Type        : {n['radio'] or 'Unknown'}\n")
                f.write(f"Auth              : {n['authentication'] or 'Unknown'}\n")
                f.write(f"Encryption        : {n['encryption'] or 'Unknown'}\n")
                f.write(f"Duplicate SSID    : {'Yes' if n['duplicate_ssid'] else 'No'}\n")
                f.write(f"Risk Score        : {n['risk_score']}/100\n")
                f.write(f"K-Means Prediction: {lbl} ({conf}% confidence)\n")
                f.write(f"Issues            :\n")
                if n["risk_reasons"]:
                    for r in n["risk_reasons"]:
                        f.write(f"  → {r}\n")
                else:
                    f.write("  → No issues detected\n")
                f.write(f"Advice            : {safety_advice(n)}\n")
                f.write("\n")

    print(f"\n{C.GREEN}✔  Report saved → {fname}{C.RESET}")

def watch_mode(interval: int = 30):
    print(f"{C.CYAN}👁  Watch mode — rescanning every {interval}s. Press Ctrl+C to stop.{C.RESET}\n")
    known_bssids = set()
    try:
        while True:
            networks = scan_wifi()
            new_nets = [n for n in networks if n["bssid"] not in known_bssids]
            if new_nets:
                print_header()
                print_network_table(networks)
                print_threat_report(networks)
                print_statistics(networks)
                for n in new_nets:
                    lbl, conf = kmeans_predict(n)
                    if lbl == "Malicious" and conf > 70:
                        print(f"\n{C.RED}🚨  NEW MALICIOUS AP DETECTED: {n['ssid']} [{n['bssid']}] — {conf}% confidence{C.RESET}")
                known_bssids = {n["bssid"] for n in networks}
            else:
                print(f"\r{C.DIM}[{datetime.now().strftime('%H:%M:%S')}] No changes detected…{C.RESET}", end="")
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{C.CYAN}Watch mode stopped.{C.RESET}")

def main():
    enable_ansi_windows()
    print_header()

    if not KMEANS_READY:
        print(f"{C.YELLOW}⚠  K-Means model not found. Run train_model.py first.{C.RESET}\n")

    print(f"{C.CYAN}📡 Scanning Wi-Fi networks…{C.RESET}")
    networks = scan_wifi()

    if not networks:
        print(f"{C.RED}No networks found. Make sure Wi-Fi is enabled.{C.RESET}")
        sys.exit(1)

    print_network_table(networks)
    print_threat_report(networks)
    print_statistics(networks)

    print(f"\n{C.BOLD}Options:{C.RESET}")
    print("  [1] Export TXT report")
    print("  [2] Export JSON report")
    print("  [3] Watch mode (auto-rescan)")
    print("  [4] Quit")
    choice = input("\nChoice: ").strip()

    if choice == "1":
        export_report(networks, "txt")
    elif choice == "2":
        export_report(networks, "json")
    elif choice == "3":
        try:
            interval = int(input("Rescan interval (seconds) [30]: ").strip() or "30")
        except ValueError:
            interval = 30
        watch_mode(interval)
    else:
        print("Bye!")

if __name__ == "__main__":
    main()