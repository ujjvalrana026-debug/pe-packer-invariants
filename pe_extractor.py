"""
EXHAUSTIVE STATIC PE FEATURE EXTRACTOR  ─  v4  (Forensically Explainable)
==========================================================================
Dissertation: Forensic Analysis of Polymorphic Malware Using Static Features
Author: Ujjval Rana


OUTPUT:
    results/pe_features_v4.csv          ← full feature table
    results/summary_report_v4.txt       ← visibility + FP rates + temporal
    results/triage_report_v4.txt        ← per-file triage decisions
    results/extracted_urls.txt          ← C2 / URL indicators
"""

import os, csv, math, hashlib, struct, string
import datetime, tempfile, shutil, re

try:
    import pefile
except ImportError:
    print("ERROR: pip install pefile"); exit(1)

try:
    import pyzipper
    HAS_PYZIPPER = True
except ImportError:
    HAS_PYZIPPER = False

# Configuration 
SAMPLES_DIR            = "samples"
OUTPUT_DIR             = "results"
CSV_FILE               = os.path.join(OUTPUT_DIR, "pe_features_v4.csv")
REPORT_FILE            = os.path.join(OUTPUT_DIR, "summary_report_v4.txt")
TRIAGE_FILE            = os.path.join(OUTPUT_DIR, "triage_report_v4.txt")
URL_FILE               = os.path.join(OUTPUT_DIR, "extracted_urls.txt")
HIGH_ENTROPY_THRESHOLD = 7.0
ZIP_PASSWORDS          = [b"infected", b"Infected", b"INFECTED", b"malware", b"virus", b""]

# Folder name that is treated as benign baseline (case-insensitive)
BENIGN_FOLDER_NAME     = "benign"


#  FORENSIC LOOKUP TABLES


PACKER_SECTIONS = {
    "upx0","upx1","upx2","upx!",".aspack",".adata","adata",
    ".themida",".winlicence",".nsp0",".nsp1",".nsp2",
    ".petite","pec2","pec1",".mpress1",".mpress2",
    "!packer",".packed",".compress",".neolit",".neolite",
    "yoda's",".yodasprotector","execryptor","_winzip_",
    ".ccg","armadillo","sfx","sfx_start","sfx_end",
    ".enigma1",".enigma2",".vmp0",".vmp1",".vmp2",
    "protect",".protect",".svmp",".vmpx",
}

STANDARD_SECTIONS = {
    ".text",".code",".data",".rdata",".rsrc",".reloc",
    ".bss",".idata",".edata",".pdata",".tls",".debug",
    ".crt",".sxdata",".gfids",".retplne",".voltbl",
    ".rodata",".ctors",".dtors",".got",".plt",
    "code","data","bss","text",".textbss",".didat",
}

UNPACK_IMPORTS = {
    "virtualalloc","virtualprotect","virtualfree",
    "writeprocessmemory","readprocessmemory",
    "createremotethread","ntunmapviewofsection",
    "rtldecompressbuffer","rtlcompressbuffer",
    "isdebuggerpresent","checkremotedebuggerpresent",
    "ntqueryinformationprocess","heapalloc","heapcreate",
}

DYN_RESOLVE_IMPORTS = {"loadlibrarya","loadlibraryw","getprocaddress"}

INJECT_IMPORTS = {
    "openprocess","createprocess","createprocessinternal",
    "zwunmapviewofsection","ntunmapviewofsection",
    "virtualallocex","writeprocessmemory",
    "createremotethread","ntcreatethread",
    "setwindowshookex","queueuserapc",
    "ntmapviewofsection","zwmapviewofsection",
}

ANTI_ANALYSIS_IMPORTS = {
    "isdebuggerpresent","checkremotedebuggerpresent",
    "outputdebugstring","ntqueryinformationprocess",
    "gettickcount","queryperformancecounter",
    "sleep","getsystemtime","getlocaltime",
    "findwindowa","findwindoww","blockinput","exitprocess",
}

CRYPTO_IMPORTS = {
    "cryptacquirecontext","cryptcreatekey","cryptencrypt",
    "cryptdecrypt","cryptimportkey","cryptderivekey",
    "bcryptencrypt","bcryptdecrypt","bcryptgeneratesymmetrickey",
    "cadesignhash","sha1","sha256","md5",
    "ncryptopenkey","ncryptencrypt","ncryptdecrypt",
}

NETWORK_IMPORTS = {
    "internetopen","internetconnect","internetopenurl",
    "httpsendrequesta","httpsendrequest","httpaddrequest",
    "wsastartup","socket","connect","send","recv",
    "winhttp","winhttpopen","winhttpsendrequest",
    "urldownloadtofile","urldownloadtofilea",
    "dnsquery","dnsqueryex","gethostbyname","getaddrinfo",
}

DYNAMIC_API_STRINGS = {
    "virtualalloc","createremotethread","writeprocessmemory",
    "loadlibrary","getprocaddress","ntdll","kernelbase",
    "ntcreatethread","zwprotectvirtualmemory",
}

MUTEX_PATTERNS = [
    r"Global\\[A-Za-z0-9_\-]{6,}",
    r"Local\\[A-Za-z0-9_\-]{6,}",
    r"[A-Fa-f0-9]{32}",
    r"_SYSTEM_[A-Z_]+_",
]
MUTEX_RE = [re.compile(p) for p in MUTEX_PATTERNS]

URL_RE    = re.compile(r'(?:https?|ftp|hxxp|hxxps)://[^\s\x00-\x1f"\'<>]{4,200}', re.IGNORECASE)
IPV4_RE   = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?::\d{1,5})?\b')
ONION_RE  = re.compile(r'[a-z2-7]{16,56}\.onion', re.IGNORECASE)
DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|ru|cn|info|biz|cc|tk|top|xyz|pw|su|ws|in|eu)\b',
    re.IGNORECASE
)
UA_RE  = re.compile(r'Mozilla/[0-9]\.[0-9][^\x00\n\r]{10,200}', re.IGNORECASE)
B64_RE = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')



#  TRIAGE SCORING ENGINE  (NEW in v4)

# Each rule: (feature_key, weight, description)
# Weights are designed so that convergence of multiple indicators pushes
# a binary into a meaningful tier.  Single indicators stay low.
TRIAGE_RULES = [
    # High-weight Tier 1 indicators (>80% visibility across families)
    ("checksum_is_zero",            12, "PE checksum zeroed (packer artefact)"),
    ("rwx_section_flag",            15, "RWX section (self-modifying unpacker)"),
    ("no_protections",              10, "No ASLR/DEP (legacy or manual build)"),
    ("dynamic_resolution_flag",     12, "LoadLibrary+GetProcAddress (import hiding)"),
    ("has_dynamic_api_strings",     10, "Dynamic API name strings in binary"),
    ("unpack_imports_flag",         10, "Unpacking API imports (VirtualAlloc etc.)"),
    ("anti_analysis_imports_flag",   8, "Anti-debug/anti-analysis API imports"),
    ("has_base64_blobs",             8, "Base64-encoded blobs (encoded payload)"),
    ("has_filepath_strings",         6, "Hardcoded file paths"),
    # Medium-weight Tier 2 indicators
    ("high_entropy_flag",            8, "High-entropy section (encrypted payload)"),
    ("has_url_strings",              6, "URL / domain strings (C2 infrastructure)"),
    ("inject_imports_flag",          8, "Process injection API imports"),
    ("has_overlay",                  5, "Overlay data (appended payload)"),
    ("raw_virtual_mismatch",         5, "Raw/virtual size mismatch (in-mem unpack)"),
    ("has_network_strings",          5, "Network/C2 strings"),
    ("has_mutex_strings",            4, "Mutex name strings"),
    # Low-weight supporting indicators
    ("suspicious_section_name",      4, "Suspicious/non-standard section name"),
    ("packer_section_detected",      6, "Known packer section name detected"),
    ("ep_is_in_last_section",        5, "Entry point in last section"),
    ("zero_imports",                 5, "Zero import table (manual loading)"),
    ("timestamp_anomaly",            3, "Timestamp anomaly (forged)"),
    ("has_tls",                      3, "TLS directory (pre-EP execution)"),
    ("has_crypto_strings",           3, "Crypto-related strings"),
    ("has_inject_strings",           4, "Injection-related strings"),
    ("network_imports_flag",         4, "Network/C2 API imports"),
]

# Max possible score if every rule fires
_MAX_TRIAGE_RAW = sum(w for _, w, _ in TRIAGE_RULES)

def triage_score(feat: dict) -> dict:
    """
    Compute a 0-100 triage score and a tier label.
    Returns dict with score, tier, fired_rules list.
    """
    raw = 0
    fired = []
    for key, weight, desc in TRIAGE_RULES:
        if feat.get(key, 0):
            raw += weight
            fired.append(desc)

    score = round(raw / _MAX_TRIAGE_RAW * 100)

    if score >= 45:
        tier = "CRITICAL"
    elif score >= 30:
        tier = "HIGH"
    elif score >= 18:
        tier = "MEDIUM"
    elif score >= 8:
        tier = "LOW"
    else:
        tier = "CLEAN"

    return {"triage_score": score, "triage_tier": tier, "triage_fired": fired}


# ── Family signature profiles
# Built from Appendix B visibility data in the dissertation.
# Format: {feature: (min_expected_visibility_pct, weight)}
# Only features with >50% visibility for that family are included.

FAMILY_PROFILES = {
    "Trickbot": {
        "unpack_imports_flag":        (63,  2),
        "anti_analysis_imports_flag": (58,  2),
        "dynamic_resolution_flag":    (58,  2),
        "has_url_strings":            (23,  1),
        "has_base64_blobs":           (95,  3),   # most distinctive Trickbot feature
        "has_filepath_strings":       (79,  2),
        "has_dynamic_api_strings":    (74,  2),
        "checksum_is_zero":           (47,  1),
        "has_overlay":                (47,  1),
    },
    "Emotet": {
        "unpack_imports_flag":        (98,  3),
        "anti_analysis_imports_flag": (96,  3),
        "dynamic_resolution_flag":    (96,  3),
        "has_dynamic_api_strings":    (98,  3),
        "checksum_is_zero":           (58,  1),
        "has_url_strings":            (20,  1),
    },
    "Formbook": {
        "high_entropy_flag":          (89,  2),
        "unpack_imports_flag":        (81,  2),
        "anti_analysis_imports_flag": (83,  2),
        "inject_imports_flag":        (72,  2),
        "network_imports_flag":       (72,  2),
        "has_dynamic_api_strings":    (83,  2),
        "has_filepath_strings":       (81,  2),
        "has_base64_blobs":           (86,  2),
        "has_tls":                    (61,  2),   # distinctive Formbook feature
        "checksum_is_zero":           (67,  1),
    },
    "Lumma": {
        "anti_analysis_imports_flag": (92,  2),
        "has_dynamic_api_strings":    (85,  2),
        "has_crypto_strings":         (85,  3),   # most distinctive Lumma feature
        "has_filepath_strings":       (92,  3),
        "suspicious_section_name":    (65,  2),
        "has_mutex_strings":          (65,  2),
    },
    "Sality": {
        "rwx_section_flag":           (100, 4),   # 100% — strongest single-family indicator
        "checksum_is_zero":           (100, 4),
        "high_entropy_flag":          (82,  2),
        "no_protections":             (80,  2),
        "anti_analysis_imports_flag": (90,  2),
        "unpack_imports_flag":        (58,  1),
    },
    "Upatre": {
        "unpack_imports_flag":        (69,  2),
        "anti_analysis_imports_flag": (72,  2),
        "no_protections":             (69,  2),
        "has_overlay":                (82,  3),   # most distinctive Upatre feature
        "checksum_is_zero":           (51,  1),
    },
    "Virut": {
        "rwx_section_flag":           (74,  3),
        "checksum_is_zero":           (100, 4),   # 100%
        "no_protections":             (95,  4),   # 95% — very distinctive
        "suspicious_section_name":    (64,  2),
        "high_entropy_flag":          (64,  1),
        "has_dynamic_api_strings":    (82,  2),
    },
    "Zeus": {
        "checksum_is_zero":           (58,  2),
        "no_protections":             (79,  3),
        "anti_analysis_imports_flag": (66,  2),
        "has_dynamic_api_strings":    (89,  2),
        "has_overlay":                (61,  2),
        "has_filepath_strings":       (55,  1),
    },
    "Emotet": {  # duplicate key resolves to last — kept for clarity
        "unpack_imports_flag":        (98,  3),
        "anti_analysis_imports_flag": (96,  3),
        "dynamic_resolution_flag":    (96,  3),
        "has_dynamic_api_strings":    (98,  3),
    },
}

def family_match(feat: dict) -> dict:
    """
    Score binary against each known family profile.
    Returns top match + confidence level.
    """
    # Skip benign samples
    if feat.get("is_malware", 1) == 0:
        return {"family_match": "N/A (benign)", "family_confidence": "N/A", "family_scores": ""}

    scores = {}
    for fam, profile in FAMILY_PROFILES.items():
        score = 0
        max_score = sum(w for _, (_, w) in profile.items())
        for key, (_, weight) in profile.items():
            if feat.get(key, 0):
                score += weight
        scores[fam] = round(score / max(max_score, 1) * 100)

    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    top_fam, top_score = ranked[0]
    second_score = ranked[1][1] if len(ranked) > 1 else 0

    # Confidence: how much better is the top match vs second?
    gap = top_score - second_score
    if top_score >= 70 and gap >= 20:
        confidence = "STRONG"
    elif top_score >= 50 and gap >= 10:
        confidence = "PROBABLE"
    elif top_score >= 30:
        confidence = "WEAK"
    else:
        confidence = "UNKNOWN"

    scores_str = " | ".join(f"{f}:{s}%" for f, s in ranked[:4])
    return {
        "family_match":      top_fam,
        "family_confidence": confidence,
        "family_scores":     scores_str,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  TEMPORAL BUCKETING  (NEW in v4)
# ══════════════════════════════════════════════════════════════════════════════

def temporal_bucket(year: int) -> str:
    """Assign a sample to a temporal analysis bucket."""
    if year == 0 or year > 2030:
        return "timestamp_invalid"
    if year < 2015:
        return "pre_2015"
    if year < 2020:
        return "2015_2019"
    if year < 2023:
        return "2020_2022"
    return "2023_plus"


# ── Helpers (unchanged from v3) 

def is_pe_bytes(d): return len(d) >= 2 and d[:2] == b"MZ"
def is_pe_file(p):
    try:
        with open(p,"rb") as f: return f.read(2) == b"MZ"
    except: return False

def sha256_of(p):
    h = hashlib.sha256()
    with open(p,"rb") as f:
        for c in iter(lambda: f.read(8192), b""): h.update(c)
    return h.hexdigest()

def md5_of(p):
    h = hashlib.md5()
    with open(p,"rb") as f:
        for c in iter(lambda: f.read(8192), b""): h.update(c)
    return h.hexdigest()

def entropy(data):
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b] += 1
    n = len(data)
    return round(-sum((c/n)*math.log2(c/n) for c in freq if c), 4)

def entropy_bucket(e):
    if e < 4.0: return 0
    if e < 5.5: return 1
    if e < 6.5: return 2
    if e < 7.0: return 3
    return 4

def ts(val):
    try: return datetime.datetime.utcfromtimestamp(val).strftime("%Y-%m-%d %H:%M:%S")
    except: return "invalid"

def extract_strings(data, min_len=4):
    result, cur = [], []
    for b in data:
        c = chr(b)
        if c in string.printable and c not in "\t\n\r\x0b\x0c":
            cur.append(c)
        else:
            if len(cur) >= min_len: result.append("".join(cur))
            cur = []
    if len(cur) >= min_len: result.append("".join(cur))
    return result

def extract_urls_from_bytes(raw_bytes, decoded_strings):
    try:
        text = raw_bytes.decode("latin-1", errors="replace")
    except:
        text = " ".join(decoded_strings)

    urls   = list({m.group() for m in URL_RE.finditer(text)})
    ips    = list({m.group() for m in IPV4_RE.finditer(text)
                  if not m.group().startswith("127.")
                  and not m.group().startswith("0.")
                  and m.group() not in ("255.255.255.255",)})
    onions = list({m.group() for m in ONION_RE.finditer(text)})
    uas    = list({m.group() for m in UA_RE.finditer(text)})
    domains_raw = {m.group() for m in DOMAIN_RE.finditer(text)}
    url_bodies  = {u.split("//")[-1].split("/")[0] for u in urls}
    domains     = list(domains_raw - url_bodies)

    return {
        "urls":    sorted(urls)[:50],
        "ips":     sorted(ips)[:50],
        "onions":  sorted(onions)[:20],
        "domains": sorted(domains)[:50],
        "uas":     sorted(uas)[:10],
    }


# ── Zip handling (unchanged from v3) 

def read_zip_member(zpath, name, pwd):
    if HAS_PYZIPPER:
        try:
            with pyzipper.AESZipFile(zpath,"r") as z:
                z.setpassword(pwd); return z.read(name)
        except: pass
    try:
        import zipfile as zf
        with zf.ZipFile(zpath,"r") as z:
            return z.read(name, pwd=pwd if pwd else None)
    except: pass
    return None

def get_namelist(zpath):
    if HAS_PYZIPPER:
        try:
            with pyzipper.AESZipFile(zpath,"r") as z: return z.namelist()
        except: pass
    try:
        import zipfile as zf
        with zf.ZipFile(zpath,"r") as z: return z.namelist()
    except: pass
    return []

def try_unzip(zpath, dest):
    found = []
    names = get_namelist(zpath)
    if not names:
        print(f"      [!] Cannot read zip — try manual extraction (pwd: infected)")
        return found
    print(f"      Contents: {names}")
    for name in names:
        data = None
        for pwd in ZIP_PASSWORDS:
            data = read_zip_member(zpath, name, pwd)
            if data: break
        if not data:
            print(f"      [!] Could not read '{name}' — manual extraction needed")
            continue
        if is_pe_bytes(data):
            safe = os.path.basename(name) or "sample"
            out  = os.path.join(dest, safe)
            with open(out,"wb") as f: f.write(data)
            found.append((out, name))
            print(f"      PE found: {name} ({len(data):,} bytes)")
        else:
            print(f"      Not a PE: {name}")
    return found

def collect_from_folder(fdir):
    collected, tmps = [], []
    files = sorted(f for f in os.listdir(fdir) if os.path.isfile(os.path.join(fdir,f)))
    print(f"  {len(files)} file(s) found")
    for fname in files:
        fpath = os.path.join(fdir, fname)
        if is_pe_file(fpath):
            print(f"  [PE] {fname}")
            collected.append((fpath, fname))
        elif fname.lower().endswith(".zip"):
            print(f"\n  [ZIP] {fname}")
            tmp = tempfile.mkdtemp(); tmps.append(tmp)
            for (pp, inner) in try_unzip(fpath, tmp):
                collected.append((pp, f"{fname}→{inner}"))
        else:
            print(f"  [SKIP] {fname}")
    return collected, tmps


# ══════════════════════════════════════════════════════════════════════════════
#  CORE FEATURE EXTRACTION  (v4 — adds is_malware, temporal_bucket, triage)
# ══════════════════════════════════════════════════════════════════════════════

def extract_features(filepath, family, label, source_note="manual"):
    try:
        pe = pefile.PE(filepath, fast_load=False)
    except Exception as e:
        print(f"    [!] pefile: {e}"); return None

    with open(filepath, "rb") as f:
        raw_bytes = f.read()

    feat = {}

    # ── Identity & provenance ──────────────────────────────────────────────────
    feat["family"]      = family
    feat["filename"]    = label
    feat["source_note"] = source_note
    feat["is_malware"]  = 0 if family.lower() == BENIGN_FOLDER_NAME else 1  # NEW

    # ── GROUP A: File-level ────────────────────────────────────────────────────
    feat["sha256"]          = sha256_of(filepath)
    feat["md5"]             = md5_of(filepath)
    feat["file_size_bytes"] = os.path.getsize(filepath)
    feat["file_entropy"]    = entropy(raw_bytes)

    # ── GROUP B: PE Header ────────────────────────────────────────────────────
    mach = pe.FILE_HEADER.Machine
    feat["architecture"]      = "x64" if mach == 0x8664 else "x86" if mach == 0x14C else f"other({hex(mach)})"
    feat["compile_timestamp"] = ts(pe.FILE_HEADER.TimeDateStamp)
    year                      = datetime.datetime.utcfromtimestamp(
                                    max(0, pe.FILE_HEADER.TimeDateStamp)
                                ).year if pe.FILE_HEADER.TimeDateStamp > 0 else 0
    feat["timestamp_year"]    = year
    feat["temporal_bucket"]   = temporal_bucket(year)   # NEW
    feat["num_sections"]      = pe.FILE_HEADER.NumberOfSections
    feat["characteristics"]   = hex(pe.FILE_HEADER.Characteristics)

    dll_chars                   = pe.OPTIONAL_HEADER.DllCharacteristics
    feat["dll_characteristics"] = hex(dll_chars)
    feat["has_aslr"]            = 1 if dll_chars & 0x0040 else 0
    feat["has_dep"]             = 1 if dll_chars & 0x0100 else 0
    feat["has_cfg"]             = 1 if dll_chars & 0x4000 else 0
    feat["no_protections"]      = 1 if (not feat["has_aslr"] and not feat["has_dep"]) else 0
    feat["subsystem"]           = pe.OPTIONAL_HEADER.Subsystem
    feat["image_base"]          = hex(pe.OPTIONAL_HEADER.ImageBase)
    feat["size_of_image"]       = pe.OPTIONAL_HEADER.SizeOfImage
    feat["size_of_headers"]     = pe.OPTIONAL_HEADER.SizeOfHeaders
    feat["small_header_flag"]   = 1 if pe.OPTIONAL_HEADER.SizeOfHeaders < 512 else 0
    feat["checksum"]            = pe.OPTIONAL_HEADER.CheckSum
    feat["checksum_is_zero"]    = 1 if pe.OPTIONAL_HEADER.CheckSum == 0 else 0
    feat["linker_version"]      = f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"
    feat["os_version"]          = f"{pe.OPTIONAL_HEADER.MajorOperatingSystemVersion}.{pe.OPTIONAL_HEADER.MinorOperatingSystemVersion}"

    used_dirs = 0
    try:
        for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            if d.VirtualAddress != 0: used_dirs += 1
    except: pass
    feat["used_data_directory_count"] = used_dirs

    has_bound = 0
    try:
        sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"]]
        has_bound = 1 if sec.VirtualAddress != 0 else 0
    except: pass
    feat["has_bound_imports"] = has_bound

    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    feat["entry_point_rva"]       = ep_rva
    feat["entry_point_section"]   = "unknown"
    feat["ep_is_in_last_section"] = 0
    for i, s in enumerate(pe.sections):
        if s.VirtualAddress <= ep_rva < s.VirtualAddress + s.Misc_VirtualSize:
            feat["entry_point_section"] = s.Name.decode(errors="replace").rstrip("\x00").strip()
            if i == len(pe.sections) - 1:
                feat["ep_is_in_last_section"] = 1
            break

    # ── GROUP C: Sections ─────────────────────────────────────────────────────
    sec_names, sec_ents = [], []
    sec_rwx = packer_sec = susp_name = rv_mis = 0
    empty_name_count = exec_sections = writable_exec_sections = 0
    entropy_hist = [0, 0, 0, 0, 0]

    for s in pe.sections:
        name = s.Name.decode(errors="replace").rstrip("\x00").strip().lower()
        sec_names.append(name or "<empty>")
        ent = entropy(s.get_data())
        sec_ents.append(ent)
        entropy_hist[entropy_bucket(ent)] += 1

        raw  = s.SizeOfRawData
        virt = s.Misc_VirtualSize
        if raw and virt / raw > 5: rv_mis = 1
        if name in PACKER_SECTIONS:    packer_sec = 1
        if name and name not in STANDARD_SECTIONS: susp_name = 1
        if not name: empty_name_count += 1

        chars    = s.Characteristics
        is_exec  = bool(chars & 0x20000000)
        is_write = bool(chars & 0x80000000)
        if is_exec: exec_sections += 1
        if is_exec and is_write:
            writable_exec_sections += 1
            sec_rwx = 1

    n_sec = len(pe.sections)
    max_e = max(sec_ents) if sec_ents else 0.0
    avg_e = round(sum(sec_ents)/n_sec, 4) if n_sec else 0.0

    feat["section_names"]               = ", ".join(sec_names)
    feat["max_section_entropy"]         = max_e
    feat["avg_section_entropy"]         = avg_e
    feat["high_entropy_flag"]           = 1 if max_e >= HIGH_ENTROPY_THRESHOLD else 0
    feat["suspicious_section_name"]     = susp_name
    feat["raw_virtual_mismatch"]        = rv_mis
    feat["packer_section_detected"]     = packer_sec
    feat["empty_section_name_count"]    = empty_name_count
    feat["exec_section_count"]          = exec_sections
    feat["rwx_section_flag"]            = sec_rwx
    feat["writable_exec_section_count"] = writable_exec_sections
    feat["entropy_bucket_0_low"]        = entropy_hist[0]
    feat["entropy_bucket_1"]            = entropy_hist[1]
    feat["entropy_bucket_2"]            = entropy_hist[2]
    feat["entropy_bucket_3"]            = entropy_hist[3]
    feat["entropy_bucket_4_high"]       = entropy_hist[4]

    # ── GROUP D: Imports/Exports ──────────────────────────────────────────────
    imp_count = unpack_count = inject_count = anti_count = crypto_count = network_count = 0
    dyn_resolve_seen = set()
    ordinal_only_count = 0
    imp_dlls = set()

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="replace").lower() if entry.dll else ""
            imp_dlls.add(dll)
            for imp in entry.imports:
                imp_count += 1
                if imp.name:
                    n = imp.name.decode(errors="replace").lower()
                    if n in UNPACK_IMPORTS:        unpack_count  += 1
                    if n in INJECT_IMPORTS:        inject_count  += 1
                    if n in ANTI_ANALYSIS_IMPORTS: anti_count    += 1
                    if n in CRYPTO_IMPORTS:        crypto_count  += 1
                    if n in NETWORK_IMPORTS:       network_count += 1
                    if n in DYN_RESOLVE_IMPORTS:   dyn_resolve_seen.add(n)
                else:
                    ordinal_only_count += 1

    total_imp = max(imp_count, 1)
    feat["import_count"]                = imp_count
    feat["import_dll_count"]            = len(imp_dlls)
    feat["zero_imports"]                = 1 if imp_count == 0 else 0
    feat["few_imports_flag"]            = 1 if 0 < imp_count <= 5 else 0
    feat["unpack_imports_flag"]         = 1 if unpack_count > 0 else 0
    feat["unpack_imports_count"]        = unpack_count
    feat["inject_imports_flag"]         = 1 if inject_count > 0 else 0
    feat["inject_imports_count"]        = inject_count
    feat["anti_analysis_imports_flag"]  = 1 if anti_count > 0 else 0
    feat["anti_analysis_imports_count"] = anti_count
    feat["crypto_imports_flag"]         = 1 if crypto_count > 0 else 0
    feat["crypto_imports_count"]        = crypto_count
    feat["network_imports_flag"]        = 1 if network_count > 0 else 0
    feat["network_imports_count"]       = network_count
    feat["dynamic_resolution_flag"]     = 1 if ({"loadlibrarya","getprocaddress"}.issubset(dyn_resolve_seen)
                                              or {"loadlibraryw","getprocaddress"}.issubset(dyn_resolve_seen)) else 0
    feat["ordinal_only_import_count"]   = ordinal_only_count
    feat["ordinal_only_ratio"]          = round(ordinal_only_count / total_imp, 4)

    exp_count = 0
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        try: exp_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        except: pass
    feat["export_count"] = exp_count
    feat["has_exports"]  = 1 if exp_count > 0 else 0

    # ── GROUP E: Directories ──────────────────────────────────────────────────
    for dir_name, feat_key in [
        ("IMAGE_DIRECTORY_ENTRY_SECURITY", "has_digital_signature"),
        ("IMAGE_DIRECTORY_ENTRY_DEBUG",    "has_debug_directory"),
        ("IMAGE_DIRECTORY_ENTRY_TLS",      "has_tls"),
    ]:
        val = 0
        try:
            sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY[dir_name]]
            val = 1 if sec.VirtualAddress != 0 else 0
        except: pass
        feat[feat_key] = val

    res_count = 0
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        try:
            for rt in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(rt, "directory"):
                    for _ in rt.directory.entries: res_count += 1
        except: pass
    feat["resource_count"] = res_count

    overlay_offset  = pe.get_overlay_data_start_offset()
    has_overlay     = 0
    overlay_entropy = 0.0
    if overlay_offset:
        overlay_data = raw_bytes[overlay_offset:]
        if len(overlay_data) > 0:
            has_overlay     = 1
            overlay_entropy = entropy(overlay_data)
    feat["has_overlay"]     = has_overlay
    feat["overlay_entropy"] = overlay_entropy

    # ── GROUP F: Anomaly indicators ───────────────────────────────────────────
    feat["ep_rva_zero"]           = 1 if ep_rva == 0 else 0
    feat["timestamp_anomaly"]     = 1 if (year < 2000 or year > 2030) else 0
    feat["size_of_image_vs_file"] = round(feat["size_of_image"] / max(feat["file_size_bytes"],1), 2)

    feat["packing_score"] = (
        feat["high_entropy_flag"] + feat["raw_virtual_mismatch"] +
        feat["packer_section_detected"] + feat["zero_imports"] +
        feat["few_imports_flag"] + feat["unpack_imports_flag"] +
        feat["rwx_section_flag"] + feat["ep_is_in_last_section"] +
        feat["dynamic_resolution_flag"] + feat["no_protections"]
    )

    # ── GROUP G: String signals ───────────────────────────────────────────────
    strings = extract_strings(raw_bytes, min_len=5)
    all_strings_lower = " ".join(strings).lower()

    feat["total_string_count"] = len(strings)

    url_data = extract_urls_from_bytes(raw_bytes, strings)
    feat["extracted_urls"]      = " | ".join(url_data["urls"])
    feat["extracted_ips"]       = " | ".join(url_data["ips"])
    feat["extracted_onions"]    = " | ".join(url_data["onions"])
    feat["extracted_domains"]   = " | ".join(url_data["domains"])
    feat["extracted_useragents"]= " | ".join(url_data["uas"])
    feat["url_count"]           = len(url_data["urls"])
    feat["ip_count"]            = len(url_data["ips"])
    feat["has_url_strings"]     = 1 if url_data["urls"] or url_data["domains"] else 0
    feat["has_shell_strings"]   = 1 if any(x in all_strings_lower for x in ["cmd.exe","powershell","wscript","cscript"]) else 0
    feat["has_registry_strings"]= 1 if any(x in all_strings_lower for x in ["reg add","reg delete","regedit","software\\microsoft"]) else 0
    feat["has_crypto_strings"]  = 1 if any(x in all_strings_lower for x in ["encrypt","decrypt","aes","rc4","xor key","ransom","chacha"]) else 0
    feat["has_inject_strings"]  = 1 if any(x in all_strings_lower for x in ["inject","shellcode","payload","loader","reflective"]) else 0
    feat["has_network_strings"] = 1 if url_data["onions"] or any(x in all_strings_lower for x in ["c2","botnet","gate.php","panel","beacon"]) else 0

    mutex_hits = []
    for s in strings:
        for rex in MUTEX_RE:
            if rex.search(s):
                mutex_hits.append(s[:80]); break
    feat["has_mutex_strings"]   = 1 if mutex_hits else 0
    feat["extracted_mutexes"]   = " | ".join(mutex_hits[:10])

    dyn_api_hits = [s for s in strings if s.lower() in DYNAMIC_API_STRINGS]
    feat["has_dynamic_api_strings"]  = 1 if dyn_api_hits else 0
    feat["dynamic_api_string_count"] = len(dyn_api_hits)

    feat["has_useragent_strings"]  = 1 if url_data["uas"] else 0

    b64_hits = [m.group() for m in B64_RE.finditer(" ".join(strings)) if len(m.group()) >= 40]
    feat["has_base64_blobs"]   = 1 if b64_hits else 0
    feat["base64_blob_count"]  = len(b64_hits)

    path_strings = [s for s in strings if re.search(r'[A-Za-z]:\\|%[A-Z]+%', s)]
    feat["has_filepath_strings"]  = 1 if path_strings else 0
    feat["filepath_string_count"] = len(path_strings)

    # ── TRIAGE SCORING  (NEW in v4) ───────────────────────────────────────────
    triage = triage_score(feat)
    feat["triage_score"]     = triage["triage_score"]
    feat["triage_tier"]      = triage["triage_tier"]
    feat["triage_fired"]     = "; ".join(triage["triage_fired"])   # human-readable

    # ── FAMILY MATCHING  (NEW in v4) ──────────────────────────────────────────
    match = family_match(feat)
    feat["family_match"]      = match["family_match"]
    feat["family_confidence"] = match["family_confidence"]
    feat["family_scores"]     = match["family_scores"]

    pe.close()
    return feat, url_data, triage


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"pyzipper available: {HAS_PYZIPPER}")

    if not os.path.isdir(SAMPLES_DIR):
        print(f"ERROR: '{SAMPLES_DIR}/' folder not found.")
        print("Create: samples/Trickbot/  samples/Zeus/  samples/benign/")
        return

    families = sorted(d for d in os.listdir(SAMPLES_DIR)
                      if os.path.isdir(os.path.join(SAMPLES_DIR, d)))
    if not families:
        print("No subfolders in samples/"); return

    # Separate benign from malware families for reporting
    malware_families = [f for f in families if f.lower() != BENIGN_FOLDER_NAME]
    has_benign       = any(f.lower() == BENIGN_FOLDER_NAME for f in families)

    all_results   = []
    family_stats  = {}
    triage_blocks = []
    all_tmp       = []
    url_records   = []

    for family in families:
        print(f"\n{'='*60}")
        print(f"  FAMILY: {family}{'  [BENIGN BASELINE]' if family.lower()==BENIGN_FOLDER_NAME else ''}")
        print(f"{'='*60}")
        pe_files, tdirs = collect_from_folder(os.path.join(SAMPLES_DIR, family))
        all_tmp.extend(tdirs)
        family_stats[family] = {"total": len(pe_files), "parsed": 0, "features": []}

        for (fpath, label) in pe_files:
            print(f"\n  -> {label}")
            result = extract_features(fpath, family, label)
            if result:
                feat, url_data, triage = result
                all_results.append(feat)
                family_stats[family]["parsed"] += 1
                family_stats[family]["features"].append(feat)
                print(f"     OK  entropy={feat['max_section_entropy']}  "
                      f"sections={feat['num_sections']}  "
                      f"imports={feat['import_count']}  "
                      f"packing={feat['packing_score']}/10  "
                      f"triage={feat['triage_score']} ({feat['triage_tier']})")
                for url in url_data["urls"] + url_data["ips"] + url_data["onions"]:
                    url_records.append({"family": family, "sha256": feat["sha256"], "indicator": url})

                # Build triage block for report
                triage_blocks.append({
                    "family":     family,
                    "filename":   label,
                    "sha256":     feat["sha256"],
                    "score":      feat["triage_score"],
                    "tier":       feat["triage_tier"],
                    "fired":      triage["triage_fired"],
                    "fam_match":  feat["family_match"],
                    "fam_conf":   feat["family_confidence"],
                    "fam_scores": feat["family_scores"],
                    "is_malware": feat["is_malware"],
                })
            else:
                print(f"     SKIPPED")

    for td in all_tmp: shutil.rmtree(td, ignore_errors=True)

    if not all_results:
        print("\nNo results.")
        return

    # ── Write CSV ──────────────────────────────────────────────────────────────
    fields = list(all_results[0].keys())
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(all_results)
    print(f"\n[SAVED] {CSV_FILE}  ({len(all_results)} rows, {len(fields)} features)")

    # ── Write URL file ─────────────────────────────────────────────────────────
    with open(URL_FILE, "w", encoding="utf-8") as f:
        f.write("family\tsha256\tindicator\n")
        for r in url_records:
            f.write(f"{r['family']}\t{r['sha256']}\t{r['indicator']}\n")
    print(f"[SAVED] {URL_FILE}  ({len(url_records)} indicators)")

    # ══════════════════════════════════════════════════════════════════════════
    #  TRIAGE REPORT  (NEW in v4)
    # ══════════════════════════════════════════════════════════════════════════
    triage_lines = [
        "="*70,
        "  PER-FILE TRIAGE REPORT  v4",
        "  Generated by pe_extractor_v4.py",
        "="*70,
        "",
        "  TIER KEY:",
        "  CRITICAL  (score 45-100)  Multiple high-weight invariants converge",
        "  HIGH      (score 30-44)   Several strong indicators present",
        "  MEDIUM    (score 18-29)   Some indicators; worth further analysis",
        "  LOW       (score  8-17)   Weak signals; likely benign or lightly packed",
        "  CLEAN     (score  0-7)    No significant malware indicators detected",
        "",
        "  CONFIDENCE KEY (family match):",
        "  STRONG   = top family scored >=70% and 20+ points clear of next",
        "  PROBABLE = top family scored >=50% and 10+ points clear of next",
        "  WEAK     = top family scored >=30%; overlap with other families",
        "  UNKNOWN  = no family profile matched sufficiently",
        "─"*70,
    ]

    for b in sorted(triage_blocks, key=lambda x: -x["score"]):
        tag = " [BENIGN]" if not b["is_malware"] else ""
        triage_lines += [
            "",
            f"  FILE    : {b['filename']}{tag}",
            f"  SHA256  : {b['sha256']}",
            f"  FAMILY  : {b['family']}",
            f"  SCORE   : {b['score']}/100  →  {b['tier']}",
        ]
        if b["is_malware"]:
            triage_lines += [
                f"  MATCH   : {b['fam_match']}  ({b['fam_conf']})",
                f"  SCORES  : {b['fam_scores']}",
            ]
        if b["fired"]:
            triage_lines.append("  INDICATORS FIRED:")
            for rule in b["fired"]:
                triage_lines.append(f"    ✓ {rule}")
        else:
            triage_lines.append("  INDICATORS FIRED: none")
        triage_lines.append("  " + "─"*50)

    # Summary triage statistics
    malware_scores  = [b["score"] for b in triage_blocks if b["is_malware"]]
    benign_scores   = [b["score"] for b in triage_blocks if not b["is_malware"]]
    triage_lines += [
        "",
        "="*70,
        "  TRIAGE SUMMARY STATISTICS",
        "="*70,
    ]
    if malware_scores:
        triage_lines += [
            f"  Malware samples  : {len(malware_scores)}",
            f"  Mean score       : {sum(malware_scores)/len(malware_scores):.1f}",
            f"  CRITICAL tier    : {sum(1 for s in malware_scores if s>=45)}  ({sum(1 for s in malware_scores if s>=45)/len(malware_scores)*100:.0f}%)",
            f"  HIGH tier        : {sum(1 for s in malware_scores if 30<=s<45)}",
            f"  MEDIUM tier      : {sum(1 for s in malware_scores if 18<=s<30)}",
            f"  LOW / CLEAN tier : {sum(1 for s in malware_scores if s<18)}  ← missed detections",
        ]
    if benign_scores:
        triage_lines += [
            "",
            f"  Benign samples   : {len(benign_scores)}",
            f"  Mean score       : {sum(benign_scores)/len(benign_scores):.1f}",
            f"  CRITICAL tier    : {sum(1 for s in benign_scores if s>=45)}  ← FALSE POSITIVES",
            f"  HIGH tier        : {sum(1 for s in benign_scores if 30<=s<45)}  ← FALSE POSITIVES",
            f"  MEDIUM tier      : {sum(1 for s in benign_scores if 18<=s<30)}",
            f"  LOW / CLEAN tier : {sum(1 for s in benign_scores if s<18)}  (correct)",
        ]
        if malware_scores and benign_scores:
            fp_rate = sum(1 for s in benign_scores if s >= 30) / len(benign_scores) * 100
            tp_rate = sum(1 for s in malware_scores if s >= 30) / len(malware_scores) * 100
            triage_lines += [
                "",
                f"  TP rate (malware caught at score>=30)  : {tp_rate:.1f}%",
                f"  FP rate (benign flagged at score>=30)  : {fp_rate:.1f}%",
                "  NOTE: cite these numbers in your dissertation triage section.",
            ]
    triage_lines.append("="*70)

    triage_report = "\n".join(triage_lines)
    print("\n" + triage_report)
    with open(TRIAGE_FILE, "w", encoding="utf-8") as f: f.write(triage_report)
    print(f"\n[SAVED] {TRIAGE_FILE}")

    # ══════════════════════════════════════════════════════════════════════════
    #  VISIBILITY REPORT  (extended with FP% column and temporal split)
    # ══════════════════════════════════════════════════════════════════════════

    binary_features = [
        ("high_entropy_flag",            "High entropy section (>7.0)"),
        ("suspicious_section_name",      "Suspicious section name"),
        ("raw_virtual_mismatch",         "Raw/virtual size mismatch"),
        ("packer_section_detected",      "Known packer section name"),
        ("rwx_section_flag",             "RWX (write+exec) section"),
        ("ep_is_in_last_section",        "Entry point in last section"),
        ("zero_imports",                 "Zero import table"),
        ("few_imports_flag",             "Few imports (<=5, hidden)"),
        ("unpack_imports_flag",          "Unpacking imports (VirtualAlloc etc.)"),
        ("inject_imports_flag",          "Process injection imports"),
        ("anti_analysis_imports_flag",   "Anti-analysis imports"),
        ("crypto_imports_flag",          "Crypto API imports"),
        ("network_imports_flag",         "Network / C2 API imports"),
        ("dynamic_resolution_flag",      "Dynamic import resolution"),
        ("has_digital_signature",        "Has digital signature"),
        ("has_debug_directory",          "Has debug directory"),
        ("has_tls",                      "Has TLS directory"),
        ("has_overlay",                  "Has overlay data"),
        ("checksum_is_zero",             "PE checksum is zero"),
        ("timestamp_anomaly",            "Timestamp anomaly"),
        ("no_protections",               "No ASLR/DEP mitigations"),
        ("has_url_strings",              "URL / domain strings"),
        ("has_shell_strings",            "Shell command strings"),
        ("has_registry_strings",         "Registry strings"),
        ("has_crypto_strings",           "Crypto-related strings"),
        ("has_inject_strings",           "Injection-related strings"),
        ("has_network_strings",          "Network/C2 strings"),
        ("has_mutex_strings",            "Mutex name strings"),
        ("has_dynamic_api_strings",      "Dynamic API name strings"),
        ("has_useragent_strings",        "Hardcoded User-Agent strings"),
        ("has_base64_blobs",             "Base64-encoded blobs"),
        ("has_filepath_strings",         "Hardcoded file-path strings"),
    ]

    benign_feats = family_stats.get(
        next((f for f in families if f.lower()==BENIGN_FOLDER_NAME), ""), {}
    ).get("features", [])

    # Column header — malware families + optional FP% column
    col_families = malware_families
    hdr_fams = "  ".join(f"{f:>8}" for f in col_families)
    fp_hdr   = "    FP%" if has_benign else ""

    lines = [
        "", "="*70,
        "  STATIC FORENSIC FEATURE VISIBILITY REPORT  v4",
        "="*70,
        f"  Total samples   : {len(all_results)}",
        f"  Malware samples : {sum(1 for r in all_results if r.get('is_malware',1))}",
        f"  Benign baseline : {len(benign_feats)}  {'(none — add samples/benign/ folder)' if not benign_feats else ''}",
        f"  Families        : {', '.join(malware_families)}",
        "",
        f"  {'Feature':<44}  {hdr_fams}{fp_hdr}",
        f"  {'─'*44}  " + "  ".join("─"*8 for _ in col_families) + ("  ─────" if has_benign else ""),
    ]

    for (key, label) in binary_features:
        row = f"  {label:<44}  "
        for fam in col_families:
            feats = family_stats[fam]["features"]
            if feats:
                pct = sum(f.get(key, 0) for f in feats) / len(feats) * 100
                row += f"  {pct:>7.0f}%"
            else:
                row += f"  {'N/A':>8}"
        if has_benign and benign_feats:
            fp_pct = sum(f.get(key, 0) for f in benign_feats) / len(benign_feats) * 100
            row += f"  {fp_pct:>4.0f}%"
        lines.append(row)

    # ── Temporal split section ─────────────────────────────────────────────────
    TEMPORAL_BUCKETS = ["pre_2015","2015_2019","2020_2022","2023_plus"]
    BUCKET_LABELS    = {"pre_2015":"<2015","2015_2019":"2015-19","2020_2022":"2020-22","2023_plus":"2023+"}

    # Key features to track temporally (the Tier 1 invariants)
    TEMPORAL_FEATURES = [
        ("checksum_is_zero",         "PE checksum zero"),
        ("rwx_section_flag",         "RWX section"),
        ("no_protections",           "No ASLR/DEP"),
        ("unpack_imports_flag",      "Unpacking imports"),
        ("dynamic_resolution_flag",  "Dyn. resolution"),
        ("has_dynamic_api_strings",  "Dyn. API strings"),
        ("anti_analysis_imports_flag","Anti-analysis imports"),
    ]

    # Only show temporal table for families with samples in >=2 buckets
    temporal_section_added = False
    for fam in malware_families:
        feats = family_stats[fam]["features"]
        if not feats: continue
        bucket_groups = {}
        for f in feats:
            b = f.get("temporal_bucket","")
            bucket_groups.setdefault(b, []).append(f)
        populated_buckets = [b for b in TEMPORAL_BUCKETS if bucket_groups.get(b)]
        if len(populated_buckets) < 2:
            continue   # not enough temporal spread

        if not temporal_section_added:
            lines += [
                "",
                "─"*70,
                "  TEMPORAL STABILITY ANALYSIS  (Tier 1 features by era)",
                "  Addresses dissertation gap: 'no temporal analysis despite timestamps'",
                "─"*70,
            ]
            temporal_section_added = True

        bkt_hdr = "  ".join(f"{BUCKET_LABELS[b]:>9}" for b in populated_buckets)
        n_hdr   = "  ".join(f"(n={len(bucket_groups[b])})" .rjust(9) for b in populated_buckets)
        lines += [
            "",
            f"  {fam} — feature visibility by compile year",
            f"  {'Feature':<32}  {bkt_hdr}",
            f"  {'':32}  {n_hdr}",
            f"  {'─'*32}  " + "  ".join("─"*9 for _ in populated_buckets),
        ]
        for feat_key, feat_label in TEMPORAL_FEATURES:
            row = f"  {feat_label:<32}  "
            for b in populated_buckets:
                grp = bucket_groups[b]
                pct = sum(f.get(feat_key,0) for f in grp) / len(grp) * 100
                row += f"  {pct:>8.0f}%"
            lines.append(row)

    if not temporal_section_added:
        lines += [
            "",
            "  TEMPORAL ANALYSIS: Not shown — no family has samples across 2+ time buckets.",
            "  Add samples from different years to enable this analysis.",
        ]

    # ── Numeric averages ───────────────────────────────────────────────────────
    numeric_features = [
        ("num_sections",             "Sections (avg)"),
        ("import_count",             "Import count (avg)"),
        ("packing_score",            "Packing score /10 (avg)"),
        ("triage_score",             "Triage score /100 (avg)"),
        ("file_entropy",             "File entropy (avg)"),
        ("max_section_entropy",      "Max section entropy (avg)"),
        ("url_count",                "URL count (avg)"),
        ("ip_count",                 "IP count (avg)"),
        ("ordinal_only_ratio",       "Ordinal-only ratio (avg)"),
    ]
    lines += [
        "",
        "─"*70,
        "  NUMERIC AVERAGES (malware families vs benign baseline):",
        "─"*70,
        f"  {'Feature':<44}  {hdr_fams}{'    BEN' if has_benign else ''}",
    ]
    for (key, label) in numeric_features:
        row = f"  {label:<44}  "
        for fam in col_families:
            feats = family_stats[fam]["features"]
            if feats:
                avg = sum(f.get(key, 0) for f in feats) / len(feats)
                row += f"  {avg:>7.2f} "
            else:
                row += f"  {'N/A':>8}"
        if has_benign and benign_feats:
            avg = sum(f.get(key, 0) for f in benign_feats) / len(benign_feats)
            row += f"  {avg:>5.2f}"
        lines.append(row)

    lines += [
        "",
        "─"*70,
        "  INTERPRETATION:",
        "  Feature >80% malware + <10% FP  → Tier 1 forensic indicator",
        "  Feature >80% malware + 10-30% FP → Tier 2: useful but needs context",
        "  Feature <50% malware             → Tier 3: family-specific only",
        "  Triage score mean >60 for malware + <20 for benign = good separation",
        "="*70,
    ]

    report = "\n".join(lines)
    print(report)
    with open(REPORT_FILE, "w", encoding="utf-8") as f: f.write(report)
    print(f"\n[SAVED] {REPORT_FILE}")
    print(f"\nOutputs:")
    print(f"  {CSV_FILE}")
    print(f"  {REPORT_FILE}")
    print(f"  {TRIAGE_FILE}")
    print(f"  {URL_FILE}")
    if not has_benign:
        print(f"\n  TIP: Add clean DLLs/EXEs to samples/benign/ to get FP% column")
        print(f"       and TP/FP rates in the triage report.")

if __name__ == "__main__":
    main()
