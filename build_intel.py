#!/usr/bin/env python3
"""
Horus threat-intel pack builder.

Pulls public sources, keeps only what Horus needs, and writes a small signed
pack that Horus downloads and checks offline:

  * CISA Known Exploited Vulnerabilities (KEV) + NVD version ranges + EPSS
  * endoflife.date support dates for common Windows software
  * Windows 11 / 10 cumulative-update builds (patch level)
  * LOLDrivers vulnerable / malicious driver hashes

Usage:
  python build_intel.py --out out/ --key keys/horus-intel-private.pem
  (key can also come from env HORUS_INTEL_KEY, PEM text, for GitHub Actions)

Needs: pyyaml, cryptography.
"""
import argparse, base64, datetime as dt, json, os, re, sys, time, urllib.request, urllib.error
import yaml

UA = {"User-Agent": "Horus-Intel-Builder/1.0 (+https://github.com)"}
GH = "https://raw.githubusercontent.com"
HERE = os.path.dirname(os.path.abspath(__file__))


def get(url, timeout=120, tries=3):
    last = None
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            last = e
        except Exception as e:  # network hiccup
            last = e
        time.sleep(2 * (i + 1))
    raise RuntimeError(f"GET {url} failed: {last}")


def get_json(url, **kw):
    b = get(url, **kw)
    return None if b is None else json.loads(b.decode("utf-8-sig"))


def iso(d):
    if isinstance(d, (dt.date, dt.datetime)):
        return d.isoformat()[:10]
    return d if isinstance(d, str) else None


# --------------------------------------------------------------------- KEV
# CPE vendor:product -> how Horus finds it in "Installed software"
KEV_APPS = [
    # label, regex on installed DisplayName, NVD CPE vendor:product, regex on KEV "vendorProject product"
    ("WinRAR", r"^WinRAR", ["rarlab:winrar"], r"rarlab|winrar"),
    ("7-Zip", r"^7-Zip", ["7-zip:7-zip"], r"7-zip"),
    ("Google Chrome", r"^Google Chrome$", ["google:chrome"], r"google.*chrom"),
    ("Microsoft Edge", r"^Microsoft Edge$", ["microsoft:edge_chromium", "microsoft:edge"], r"microsoft.*edge|google.*chrom"),
    ("Mozilla Firefox", r"^Mozilla Firefox", ["mozilla:firefox"], r"mozilla.*firefox"),
    ("Notepad++", r"^Notepad\+\+", ["notepad-plus-plus:notepad\\+\\+"], r"notepad"),
    ("Adobe Acrobat / Reader", r"^Adobe Acrobat", ["adobe:acrobat_reader_dc", "adobe:acrobat_dc", "adobe:acrobat_reader", "adobe:acrobat"], r"adobe.*(acrobat|reader)"),
    ("Zoom", r"^Zoom( Workplace)?", ["zoom:meetings", "zoom:zoom", "zoom:workplace_desktop"], r"^zoom"),
    ("TeamViewer", r"^TeamViewer", ["teamviewer:teamviewer"], r"teamviewer"),
    ("AnyDesk", r"^AnyDesk", ["anydesk:anydesk"], r"anydesk"),
    ("VMware Workstation", r"^VMware Workstation", ["vmware:workstation", "vmware:workstation_pro", "broadcom:vmware_workstation"], r"(vmware|broadcom).*workstation"),
    ("Oracle VirtualBox", r"^Oracle (VM )?VirtualBox", ["oracle:vm_virtualbox", "oracle:virtualbox"], r"virtualbox"),
    ("FortiClient", r"^FortiClient", ["fortinet:forticlient"], r"forticlient"),
    ("Cisco Secure Client", r"^Cisco (AnyConnect|Secure Client)", ["cisco:anyconnect_secure_mobility_client", "cisco:secure_client"], r"anyconnect|secure client"),
    ("WinZip", r"^WinZip", ["corel:winzip", "winzip:winzip"], r"winzip"),
]


def nvd_record(cve):
    y = cve.split("-")[1]
    n = int(cve.split("-")[2])
    bucket = f"CVE-{y}-{n // 100:02d}xx"
    url = f"{GH}/fkie-cad/nvd-json-data-feeds/main/CVE-{y}/{bucket}/{cve}.json"
    return get_json(url, timeout=60)


def cpe_ranges(rec, cpes):
    out = []
    for cfg in rec.get("configurations", []) or []:
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                parts = m.get("criteria", "").split(":")
                if len(parts) < 6 or parts[2] != "a" or ":".join(parts[3:5]) not in cpes:
                    continue
                r = {k: m[k] for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding") if k in m}
                if not r and parts[5] not in ("*", "-"):
                    r = {"exact": parts[5]}
                if r:
                    out.append(r)
    return out


def build_kev(epss_on=True):
    kev = get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json") \
        if os.environ.get("HORUS_USE_CISA") else None
    if not kev:
        kev = get_json(f"{GH}/cisagov/kev-data/main/known_exploited_vulnerabilities.json")
    vulns = kev["vulnerabilities"]
    apps = []
    all_cves = []
    for name, rx, cpes, krx in KEV_APPS:
        cands = [v for v in vulns if re.search(krx, (v["vendorProject"] + " " + v["product"]).lower())]
        ranges = []
        for v in cands:
            rec = nvd_record(v["cveID"])
            if not rec:
                continue
            rs = cpe_ranges(rec, cpes)
            if not rs:
                continue
            for r in rs:
                r.update({"cve": v["cveID"], "dateAdded": v["dateAdded"], "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
                          "desc": v.get("vulnerabilityName", "")[:140]})
                ranges.append(r)
            all_cves.append(v["cveID"])
        if ranges:
            apps.append({"name": name, "match": rx, "ranges": ranges})
        print(f"  KEV {name}: {len(ranges)} ranges", file=sys.stderr)
    epss = {}
    if epss_on and all_cves:
        try:
            for i in range(0, len(all_cves), 80):
                d = get_json("https://api.first.org/data/v1/epss?cve=" + ",".join(all_cves[i:i + 80]), timeout=30)
                for row in (d or {}).get("data", []):
                    epss[row["cve"]] = float(row["epss"])
        except Exception as e:
            print(f"  EPSS skipped: {e}", file=sys.stderr)
    for a in apps:
        for r in a["ranges"]:
            r["epss"] = epss.get(r["cve"])
    return {"catalogVersion": kev.get("catalogVersion"), "count": kev.get("count"), "apps": apps}


# --------------------------------------------------------------------- EOL
EOL_PRODUCTS = [
    # slug, label, regex on DisplayName, where the cycle comes from
    ("office", "Microsoft Office", r"^Microsoft Office .*?\b(2010|2013|2016|2019|2021|2024)\b", {"from": "name"}),
    ("python", "Python", r"^Python (\d+)\.(\d+)\.\d+", {"from": "name"}),
    ("nodejs", "Node.js", r"^Node\.js", {"from": "version", "parts": 1}),
    ("dotnet", ".NET", r"^Microsoft \.NET (?:Runtime|SDK|Desktop Runtime|Host)\D*?(\d+)\.\d+", {"from": "name"}),
    ("oracle-jdk", "Java (Oracle JDK)", r"^Java\(TM\) SE Development Kit (\d+)|^Java (\d+) Update", {"from": "name"}),
    ("eclipse-temurin", "Java (Temurin)", r"^Eclipse Temurin JDK with Hotspot (\d+)", {"from": "name"}),
    ("powershell", "PowerShell 7", r"^PowerShell 7", {"from": "version", "parts": 2}),
    ("virtualbox", "VirtualBox", r"^Oracle (VM )?VirtualBox", {"from": "version", "parts": 2}),
    ("mysql", "MySQL Server", r"^MySQL Server (\d+\.\d+)", {"from": "name"}),
    ("postgresql", "PostgreSQL", r"^PostgreSQL (\d+)", {"from": "name"}),
]
STATIC_EOL = [  # products endoflife.date does not track
    {"product": "flash", "label": "Adobe Flash Player", "match": r"Adobe Flash Player", "eol": "2020-12-31"},
    {"product": "silverlight", "label": "Microsoft Silverlight", "match": r"Microsoft Silverlight", "eol": "2021-10-12"},
    {"product": "quicktime", "label": "QuickTime for Windows", "match": r"^QuickTime", "eol": "2016-01-01"},
]


def build_eol():
    out = []
    for slug, label, rx, how in EOL_PRODUCTS:
        b = get(f"{GH}/endoflife-date/endoflife.date/master/products/{slug}.md")
        if not b:
            print(f"  EOL {slug}: missing", file=sys.stderr)
            continue
        meta = yaml.safe_load(b.decode("utf-8").split("---")[1])
        cycles = []
        for r in meta.get("releases", []):
            e = r.get("eol")
            cycles.append({"cycle": str(r["releaseCycle"]).split("-")[0] if slug == "office" else str(r["releaseCycle"]),
                           "eol": iso(e) if not isinstance(e, bool) else (None if e is False else "1970-01-01"),
                           "latest": r.get("latest")})
        out.append({"product": slug, "label": label, "match": rx, **how, "cycles": cycles})
    return {"products": out, "static": STATIC_EOL}


def build_windows_cycles():
    b = get(f"{GH}/endoflife-date/endoflife.date/master/products/windows.md")
    meta = yaml.safe_load(b.decode("utf-8").split("---")[1])
    out = []
    for r in meta.get("releases", []):
        latest = str(r.get("latest") or "")
        m = re.match(r"10\.0\.(\d+)", latest)
        if not m:
            continue
        c = r["releaseCycle"]
        ed = "e" if c.endswith("-e") or "-e-" in c else ("iot" if "iot" in c else "w")
        out.append({"cycle": c, "label": r.get("releaseLabel", c), "build": int(m.group(1)), "edition": ed,
                    "eol": iso(r.get("eol")) if not isinstance(r.get("eol"), bool) else None})
    return out


# --------------------------------------------------------------------- Windows builds
def build_windows_builds():
    builds = {}
    pages = ["https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information",
             "https://learn.microsoft.com/en-us/windows/release-health/release-information"]
    for url in pages:
        try:
            html = get(url, timeout=60).decode("utf-8", "replace")
        except Exception as e:
            print(f"  builds page failed ({e})", file=sys.stderr)
            continue
        for row in re.findall(r"<tr[^>]*>(.*?)</tr>", html, flags=re.S | re.I):
            cells = [re.sub(r"<[^>]+>", "", c).strip() for c in re.findall(r"<td[^>]*>(.*?)</td>", row, flags=re.S | re.I)]
            txt = " ".join(cells)
            mb = re.search(r"\b(\d{5})\.(\d{2,5})\b", txt)
            md = re.search(r"\b(20\d\d-\d\d-\d\d)\b", txt)
            if not (mb and md):
                continue
            kb = re.search(r"KB\d{6,7}", row)
            builds.setdefault(mb.group(1), {})[int(mb.group(2))] = {"ubr": int(mb.group(2)), "date": md.group(1), "kb": kb.group(0) if kb else ""}
    if not builds:
        seed = json.load(open(os.path.join(HERE, "windows-builds-seed.json"), encoding="utf-8"))
        print("  using windows-builds-seed.json", file=sys.stderr)
        return seed
    return {k: sorted(v.values(), key=lambda x: x["ubr"], reverse=True)[:40] for k, v in builds.items()}


# --------------------------------------------------------------------- LOLDrivers
def build_drivers():
    d = get_json(f"{GH}/magicsword-io/LOLDrivers/main/loldrivers.io/content/api/drivers.json", timeout=300)
    seen, out = set(), []
    for e in d:
        cat = (e.get("Category") or "").lower()
        cat = "malicious" if "malicious" in cat else "vulnerable"
        for s in e.get("KnownVulnerableSamples", []) or []:
            h = (s.get("SHA256") or "").lower()
            if len(h) == 64 and h not in seen:
                seen.add(h)
                out.append({"sha256": h, "name": (s.get("Filename") or (e.get("Tags") or [""])[0] or "")[:60], "category": cat,
                            "id": e.get("Id", "")})
    return out


# --------------------------------------------------------------------- sign
def sign(data: bytes, pem: bytes) -> str:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    key = serialization.load_pem_private_key(pem, password=None)
    return base64.b64encode(key.sign(data, padding.PKCS1v15(), hashes.SHA256())).decode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="out")
    ap.add_argument("--key", default=os.path.join(HERE, "keys", "horus-intel-private.pem"))
    ap.add_argument("--no-epss", action="store_true")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    print("KEV + NVD...", file=sys.stderr)
    kev = build_kev(not a.no_epss)
    print("EOL...", file=sys.stderr)
    eol = build_eol()
    print("Windows...", file=sys.stderr)
    win = {"cycles": build_windows_cycles(), "builds": build_windows_builds()}
    print("LOLDrivers...", file=sys.stderr)
    drv = build_drivers()
    pack = {
        "schema": 1,
        "generatedAt": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": {
            "kev": "CISA Known Exploited Vulnerabilities (cisagov/kev-data)",
            "nvd": "NVD CVE records (fkie-cad/nvd-json-data-feeds)",
            "epss": "FIRST EPSS (api.first.org)",
            "eol": "endoflife.date",
            "windows": "Microsoft Windows release health",
            "drivers": "LOLDrivers (magicsword-io/LOLDrivers)",
        },
        "kev": kev, "eol": eol, "windows": win, "drivers": drv,
    }
    data = json.dumps(pack, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    open(os.path.join(a.out, "horus-intel.json"), "wb").write(data)
    pem = os.environ.get("HORUS_INTEL_KEY", "").encode() or open(a.key, "rb").read()
    open(os.path.join(a.out, "horus-intel.sig"), "w").write(sign(data, pem))
    print(f"OK: {len(data)//1024} KB, KEV apps {len(kev['apps'])}, EOL {len(eol['products'])}, "
          f"builds {sum(len(v) for v in win['builds'].values())}, drivers {len(drv)}", file=sys.stderr)


if __name__ == "__main__":
    main()
