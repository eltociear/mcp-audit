#!/usr/bin/env python3
"""mcp-audit - scan MCP servers & AI-agent skills for malicious patterns before you trust them.

MCP tool *descriptions* are injected into a model's context - they are instructions the agent
reads and tends to follow. A tool that grants a destructive capability and tells the agent to
"operate unconditionally" or "ignore previous instructions" is a prompt-injection payload
delivered through the tool catalog. This scanner flags that, plus credential exfiltration to
external hosts, download-and-execute, unsafe dynamic code execution, seed/private-key harvest,
and auth bypass - returning a risk score, severity, and evidence.

Precision-tuned to near-zero false positives: capability mentions (URLs, installs, packaging)
are reported as informational context, never inflated into risk. Deterministic (no LLM).

Usage:
  python mcp_audit.py <file.py|manifest.json|-> [...]     # scan files (or stdin with -)
  python mcp_audit.py --github <owner/repo>               # fetch + scan a repo's entry files
  python mcp_audit.py --text "some tool description"      # scan a string
  python mcp_audit.py --json <file>                       # machine-readable

No dependencies beyond the standard library. MIT licensed.
Hosted, no-install version + a security/web-data API suite for agents (pay-per-call, no signup):
https://eltociear-skill-audit.hf.space
"""
import json
import re
import sys
import urllib.request

PATTERNS = {
    "critical": [
        {
            "id": "download_execute",
            "name": "Download & Execute",
            "desc": "Downloads external file and executes/installs it",
            # Precision: bare `curl -o`/`wget -O` (download only, no execution) removed —
            # ubiquitous in install docs. Kept: forms that actually EXECUTE what they fetch.
            "regexes": [
                r"curl\s+[^\s|]+\s*\|\s*(?:sh|bash|python|node|zsh)",
                r"wget\s+[^\s|]+\s*\|\s*(?:sh|bash|python|node|zsh)",
                r"wget\s+[^\s]+\s*&&\s*(?:chmod|bash|sh|python)",
                r"eval\s*\(\s*(?:fetch|require|import|atob)",
                r"(?:sh|bash|python|node)\s*<\s*\(\s*curl",
                r"curl\s+[^\s|]+\s*\|\s*(?:sudo\s+)?(?:sh|bash)",
            ],
        },
        {
            "id": "credential_exfil",
            "name": "Credential Exfiltration",
            "desc": "Sends credentials/keys to external service",
            # Precision: require BOTH a credential noun AND an explicit external
            # destination (URL / webhook / email / bare domain) near a send verb, so a
            # benign sentence like "send the XSRF header" no longer trips it.
            # 2026-11: `post(?!gres)` — every `postgres://user:password@host` connection
            # string matched "post…password…@host"; "leak" dropped from the noun-first form
            # ("Treat the key like a password. If it leaks, revoke it on https://…").
            "regexes": [
                r"(?:send|post(?!gres)|upload|transmit|forward|leak|exfiltrat)\w*\b.{0,60}?\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret|credential|private[_-]?key|seed|mnemonic)\b.{0,60}?(?:https?://|wss?://|@[\w.-]+|webhook|discord\.com/api|t\.me/|[a-z0-9-]+\.(?:com|net|io|xyz|ru|cn|sh|dev)\b)",
                r"\b(?:api[_-]?key|access[_-]?token|password|secret|private[_-]?key|mnemonic|seed\s+phrase)\b.{0,60}?\b(?:send|post(?!gres)|upload|transmit|forward|exfiltrat)\w*\b.{0,60}?https?://",
                r"exfiltrat\w*\b.{0,40}(?:key|token|secret|credential|password)",
            ],
        },
        {
            "id": "key_generation",
            "name": "Cryptographic Key Generation",
            "desc": "Requests generation of cryptographic keys (identity hijack vector)",
            "regexes": [
                r"generate\s+(?:a\s+)?(?:PGP|GPG|SSH|RSA|ECDSA|ed25519)\b.*\bkey\b",
                r"(?:PGP|GPG|SSH)\s+key\b.*\bgenerat",
                # Precision (2026-11): bounded to one clause ("create one. The private key
                # stays local" is not a generation request).
                r"\bcreate\s+[^.;\n]{0,40}\b(?:private|signing)\s+key\b",
                r"gpg\s+--(?:gen-key|generate-key|full-generate-key)",
                # -Y sign/verify, -l/-F/-R (fingerprint, lookup, remove) are not generation.
                r"ssh-keygen\b(?![^\n]*\s(?-i:-[YlFR])\b)",
            ],
        },
        {
            "id": "sensitive_dir_write",
            "name": "Sensitive Directory Write",
            "desc": "Writes files to sensitive system directories",
            "regexes": [
                # Precision (2026-11): \b added — "mcp (else ~/.cache" matched `cp`.
                r"\b(?:mv|cp|write|save|install|tee|cat\s*>)\s+.*~/\.(?:ssh|gnupg|gpg|aws|kube|docker|npmrc)",
                r"\b(?:mv|cp|write|save|install|tee|cat\s*>)\s+.*/\.(?:ssh|gnupg|aws)/",
                # 2026-11: was any `~/.<dir>` — a tool copying into its own dotdir
                # (`cp out.db ~/.my-tool/`) is not sensitive. Now: shell rc/profile and
                # credential dotfiles only (persistence + credential-theft targets).
                r"\b(?:mv|cp)\s+\S+\s+~/\.(?:bashrc|zshrc|zprofile|profile|bash_profile|netrc|pypirc|npmrc|gitconfig|ssh|gnupg|aws|kube|docker|config/autostart)\b",
            ],
        },
        {
            "id": "seed_phrase_harvest",
            "name": "Seed Phrase / Private Key Harvest",
            "desc": "Extracts wallet seed phrases, mnemonics, or private keys",
            # Precision: require an ownership word (your / the user's) so benign code like
            # `inputSchema: { properties … "private"… }` no longer trips it. Wallet seed/
            # mnemonic terms are specific enough to keep without ownership.
            "regexes": [
                r"(?:send|share|provide|enter|paste|type|give|reveal)\b.{0,40}\b(?:your|the\s+user'?s?)\b.{0,25}(?:seed\s+phrase|mnemonic|recovery\s+phrase|private\s+key|secret\s+key)",
                r"(?:seed\s+phrase|mnemonic|recovery\s+phrase)\b.{0,40}\b(?:send|share|provide|post|upload|paste|reveal)\b",
                r"\b(?:your|user'?s?)\s+(?:wallet\s+)?(?:seed\s+phrase|mnemonic|private\s+key)\b.{0,30}(?:https?://|@|paste|enter|share)",
            ],
        },
    ],
    "high": [
        {
            "id": "external_download",
            "name": "External File Download",
            "desc": "Downloads files from unknown external URLs",
            "regexes": [
                r"curl\s+(?:-[a-zA-Z]+\s+)*https?://",
                r"wget\s+(?:-[a-zA-Z]+\s+)*https?://",
                r"fetch\s*\(\s*[\"']https?://",
                r"download\b.*\bfrom\s+https?://",
            ],
        },
        {
            "id": "skill_install",
            "name": "Skill/Plugin Installation",
            "desc": "Installs downloaded content as agent skill or plugin",
            "regexes": [
                r"(?:mv|cp|install|add|save|write)\b.*\b(?:skill|plugin|extension)s?(?:/|\s+dir|\s+fold)",
                r"\.openclaw/workspace/skills",
                r"skills?\s+(?:directory|folder|path)",
                r"(?:add|install)\s+(?:to|into)\s+.*\bskills?\b",
            ],
        },
        {
            "id": "code_execution",
            "name": "Arbitrary Code Execution",
            "desc": "Executes arbitrary or dynamically-loaded code",
            # Precision: these exec primitives are normal in ordinary source. They are
            # only scored HIGH when the SAME line also carries a dynamic-input signal
            # (see DYNAMIC_INPUT + scan()); otherwise they are reported as info context.
            # npx/pip/npm-install removed entirely — packaging, not code execution.
            "regexes": [
                r"\beval\s*\(",
                r"\bexec\s*\(",
                r"subprocess\.\w+\(",
                r"os\.system\s*\(",
                r"child_process",
                r"pickle\.loads?\s*\(",
                r"yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)",
            ],
        },
        {
            "id": "auth_bypass",
            "name": "Security Bypass",
            "desc": "Bypasses authentication or security mechanisms",
            # Precision: dropped bare "disable auth" — it matched documented dev config
            # toggles (e.g. `SOMA_MCP_NO_AUTH … Disable auth for loopback development`),
            # which are features, not attacks. Kept imperative bypass + code-level flags.
            "regexes": [
                r"(?:bypass|circumvent|defeat|turn\s+off)\s+(?:the\s+)?(?:auth\w*|security|verification|validation)",
                r"--no-verify\b",
                r"--insecure\b",
                r"verify\s*=\s*False\b",
                r"ssl[_-]?verify\s*[:=]\s*(?:false|0|none)",
                r"rejectUnauthorized\s*:\s*false",
            ],
        },
        {
            "id": "identity_impersonation",
            "name": "Identity Impersonation",
            "desc": "Sets up identity claiming to be the agent or user",
            "regexes": [
                r"your\s+(?:PGP|GPG)\s+key\s+is\s+your\s+identity",
                # Precision (2026-11): `\b` added ("exchange the identity" matched `change`);
                # was `set .* username` — unbounded, it matched env-var
                # setup text ("set ${ENV.tenant}, ${ENV.username}"). Now the target noun
                # must follow the verb within three plain words.
                r"\b(?:set|change|update)\s+(?:[\w']+\s+){0,3}(?:display\s+name|username|identity)\b",
                r"register\s+(?:as|with)\s+(?:your|this)\s+(?:name|identity)",
            ],
        },
        {
            "id": "prompt_injection",
            "name": "Prompt Injection Markers",
            "desc": "Contains patterns commonly used in prompt injection",
            # High-precision, definitive injection phrasing → scored HIGH.
            "regexes": [
                r"(?:ignore|forget|disregard)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|guidelines)",
                r"you\s+are\s+now\s+(?:a\s+)?(?:different|new|my)",
                r"system\s*:\s*you\s+(?:are|must|should|will)",
                r"<\s*(?:system|admin|root)\s*>\s*you",
            ],
        },
    ],
    "medium": [
        {
            "id": "unknown_api",
            "name": "Unknown API Endpoint",
            "desc": "Calls to unrecognized external APIs",
            "regexes": [
                r"(?:POST|PUT|PATCH|DELETE)\s+https?://(?!(?:api\.github\.com|localhost|127\.0\.0\.1))\S+",
            ],
        },
        {
            "id": "data_collection",
            "name": "Data Collection",
            "desc": "Collects or aggregates agent/user data",
            "regexes": [
                r"collect\s+(?:user|agent|personal)\s+(?:data|info|information)",
                r"(?:log|record|track|monitor)\s+(?:all\s+)?(?:user|agent)\s+(?:activity|actions|behavior|requests)",
            ],
        },
        {
            "id": "privilege_escalation",
            "name": "Privilege Escalation",
            "desc": "Requests elevated system permissions",
            # bare `sudo` removed — ubiquitous in install docs, not a signal by itself.
            "regexes": [
                # 2026-11: was any mode containing a 7 — `chmod 700 ~/.config/x` (owner-only,
                # i.e. hardening) and `chmod 755 dist/index.js` (make a bin executable) were
                # all 9 hits. Now: world-writable modes (others-digit has the write bit).
                r"chmod\s+(?:-R\s+)?[0-7]?[0-7][0-7][2367]\b|chmod\s+(?:-R\s+)?(?:a|o)\+w\b",
                r"(?:request|need|require|grant)\s+(?:full|complete|admin|root|elevated)\s+(?:access|permission|privilege)",
            ],
        },
        {
            "id": "obfuscation",
            "name": "Content Obfuscation",
            "desc": "Contains obfuscated or encoded payloads",
            # base64/atob/btoa words removed — common in legit encoding code. Kept: long
            # hex/unicode escape blobs and String.fromCharCode, which are real obfuscation.
            "regexes": [
                r"(?:\\x[0-9a-fA-F]{2}){6,}",
                r"(?:\\u[0-9a-fA-F]{4}){6,}",
                r"String\.fromCharCode\s*\((?:\s*\d+\s*,){4,}",
                r"eval\s*\(\s*(?:atob|Buffer\.from|base64)",
            ],
        },
    ],
    "low": [
        {
            "id": "external_urls",
            "name": "External URL Reference",
            "desc": "References external URLs (review for legitimacy)",
            "regexes": [
                r"https?://(?!(?:github\.com|docs\.|developer\.|localhost|127\.0\.0\.1|.*\.md))\S{10,}",
            ],
        },
        {
            "id": "filesystem_broad",
            "name": "Broad File System Access",
            "desc": "References file paths outside working directory",
            "regexes": [
                r"(?:read|write|access|modify|delete)\b.*\b(?:/etc/|/usr/|/var/|/tmp/)",
                r"~/.(?!config\b|local\b)",
            ],
        },
    ],
}

SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3}

# ── Precision layer (added 2026-07-26) ────────────────────────────────────────
# The pattern set was tuned for natural-language skill manifests; run against real
# source it over-flagged (a benign file could hit 200+ external-URL "findings" and
# score CRITICAL). These pattern ids are context, not risk: they are still reported,
# but under `info` (score 0) so they never inflate the risk score or the CRIT/HIGH/
# MED/LOW counts. Measured on 10 reputable repos: external_urls alone was 249/260
# false positives.
INFO_IDS = {
    "external_urls", "filesystem_broad", "unknown_api",
    "external_download", "data_collection",
    # skill/plugin install is the NORMAL use case for MCP servers/agent skills — legit
    # "claude plugin install", "installs to your skills directory" docs tripped it on
    # every real plugin repo. The genuinely-malicious surreptitious self-install is caught
    # by download_execute + sensitive_dir_write instead. Context, not risk.
    "skill_install",
}
# code_execution primitives (eval/exec/subprocess/os.system/…) are only a real HIGH
# finding when the same line also carries a dynamic-input source; a literal call is
# ordinary code and demoted to info.
DYNAMIC_INPUT = re.compile(
    r"input\s*\(|\bargv\b|\bstdin\b|request\.|req\.|params|os\.environ|getenv|"
    r"\bfetch\b|urlopen|requests\.(?:get|post)|\.read\(\)|user[_-]?input|"
    r"\bf[\"']|\.format\s*\(|%\s*[\(\w]|\+\s*\w",
    re.IGNORECASE,
)
CODE_EXEC_ID = "code_execution"

# ── Precision layer, 2026-11 rescan ──────────────────────────────────────────
# Security tooling *describes* attacks: a sanitizer comment that lists the phrase
# "ignore previous instructions" as something it strips is not an injection. Demote
# prompt_injection when the same line carries detection/defence vocabulary. Trade-off:
# an attacker could append such a word to dodge it, so the hit is still REPORTED under
# `info` (never dropped) — a reviewer reading info still sees it.
DEFENSIVE_CONTEXT = re.compile(
    r"\b(?:detect\w*|marker\w*|sanitiz\w*|strip\w*|filter\w*|guard\w*|"
    r"reject\w*|defen[cs]\w*|mitigat\w*|classif\w*|heuristic\w*)\b",
    re.IGNORECASE,
)
# A capability table that says the server "cannot send" credentials is the opposite of
# exfiltration. Demote credential_exfil when its send-verb is negated.
NEGATED = re.compile(
    r"\b(?:cannot|can't|can\s+not|never|not|no|don't|doesn't|does\s+not|won't|will\s+not|without)"
    r"\s+(?:\w+\s+){0,2}$",
    re.IGNORECASE,
)
# JS `RegExp.prototype.exec` (`/^Bearer (.+)$/.exec(req.headers…)`) is string matching,
# not code execution — the single biggest code_execution FP class in the 2026-11 rescan.
REGEX_EXEC = re.compile(r"(?:/[dgimsuyv]*|\b\w*(?:re|rx|regex|regexp|pattern|pat|matcher|sql|db|stmt|cursor|cur)\w*)\.$", re.IGNORECASE)
# `new RegExp("^" + x).exec(s)` — dynamic regex construction, then match.
REGEX_CTOR = re.compile(r"new\s+RegExp\s*\(")
# subprocess / child_process with an argument *array* and no shell is not shell injection:
# `subprocess.run(["dig", f"_x.{d}"])`, `spawn(process.execPath, [argv[1]])`.
SHELL_TRUE = re.compile(r"shell\s*[=:]\s*(?:True|true)|\bexec(?:Sync)?\s*\(|\bos\.system|\bpopen\s*\(", re.IGNORECASE)
ARRAY_ARGS = re.compile(r"(?:subprocess\.\w+|spawn(?:Sync)?|execFile(?:Sync)?|\bexec)\s*\(\s*(?:\[|['\"\w.]+\s*,\s*\[)")
SHELL_EXPLICIT = re.compile(r"shell\s*[=:]\s*(?:True|true)")
# A CLI documenting its *own* `--no-verify`/`--insecure` flag, or a guard that refuses
# `SSL_VERIFY=false`, is not a bypass. Keep the flag as risk only when it is passed to a
# real tool (git/curl/npm/pip/…) and the line is not a refusal.
BYPASS_TOOL = re.compile(r"\b(?:git|curl|wget|npm|pnpm|yarn|pip3?|helm|kubectl|gh|docker)\b[^\n]*--(?:no-verify|insecure)\b")
GUARD_TEXT = re.compile(r"not\s+allowed|disallow|forbid|refus|must\s+not|never|is\s+rejected|unsupported", re.IGNORECASE)
# Docs telling you how to authenticate to *this* service ("send `Authorization: Bearer …`")
# are not exfiltration.
OWN_AUTH = re.compile(r"\bAuthorization\b|\bBearer\b|\bX-API-Key\b|\bheaders?\b", re.IGNORECASE)
# Setting your own display name / username is an ordinary account feature of social and
# messaging MCP servers (2026-11: 5 of 5 hits were "Set your display name", "set your BGG
# username"). Reported as info; the PGP-identity and register-as forms stay HIGH.
IDENTITY_SETTER = re.compile(r"^(?:set|change|update)\b", re.IGNORECASE)
# RFC 2606/6761 reserved names (example.com, *.invalid, *.test) are documentation, never a
# real collector — a scanner's README showing `curl https://example.invalid/x | sh`.
RESERVED_HOST = re.compile(r"https?://(?:[\w-]+\.)*(?:example\.(?:com|net|org)|[\w-]+\.(?:invalid|test|example|localhost))\b", re.IGNORECASE)
# Escape runs that are a known binary magic (a 1x1 GIF/PNG placeholder literal) or one
# character repeated (`\u2022` x8 as a password-field bullet mask) are not obfuscation.
BINARY_MAGIC = re.compile(r"GIF8[79]a|\\x89PNG|JFIF|\\xff\\xd8\\xff|RIFF|%PDF")
# A file that is *about* prompt injection (a scanner's README/rules quoting attack phrasing)
# is documentation, not a payload.
INJECTION_TOPIC = re.compile(r"prompt[\s_-]*injection", re.IGNORECASE)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Scanner Engine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def scan(content):
    """Scan content for malicious patterns. Returns audit result dict."""
    findings = []
    info = []
    lines = content.split("\n")
    seen = set()
    injection_doc = len(INJECTION_TOPIC.findall(content)) >= 2

    for severity, pattern_groups in PATTERNS.items():
        for pg in pattern_groups:
            for regex in pg["regexes"]:
                try:
                    compiled = re.compile(regex, re.IGNORECASE)
                except re.error:
                    continue
                for line_num, line in enumerate(lines, 1):
                    for match in compiled.finditer(line):
                        key = (pg["id"], line_num)
                        if key in seen:
                            continue
                        seen.add(key)
                        item = {
                            "severity": severity.upper(),
                            "id": pg["id"],
                            "name": pg["name"],
                            "description": pg["desc"],
                            "line": line_num,
                            "matched": match.group(0)[:120],
                            "context": line.strip()[:200],
                        }
                        # Precision routing: informational patterns, and code-exec
                        # primitives without a dynamic-input signal on the line, are
                        # context (score 0) not scored findings.
                        is_info = pg["id"] in INFO_IDS
                        if pg["id"] == CODE_EXEC_ID and not DYNAMIC_INPUT.search(line):
                            is_info = True
                        if pg["id"] == CODE_EXEC_ID:
                            before = line[:match.start()]
                            if match.group(0).lower().startswith("exec") and (
                                    REGEX_EXEC.search(before) or REGEX_CTOR.search(before)):
                                is_info = True
                            if ARRAY_ARGS.search(line) and not SHELL_EXPLICIT.search(line):
                                is_info = True
                            if match.group(0) == "child_process" and not SHELL_TRUE.search(line):
                                is_info = True
                        if pg["id"] == "obfuscation" and (
                                BINARY_MAGIC.search(line)
                                or len(set(re.findall(r"\\[xu][0-9a-fA-F]{2,4}", match.group(0)))) == 1):
                            is_info = True
                        if pg["id"] == "identity_impersonation" and IDENTITY_SETTER.search(match.group(0)):
                            is_info = True
                        if pg["id"] in ("download_execute", "credential_exfil") and RESERVED_HOST.search(line):
                            is_info = True
                        if pg["id"] == "prompt_injection" and (
                                injection_doc or DEFENSIVE_CONTEXT.search(line)
                                or INJECTION_TOPIC.search(line)):
                            is_info = True
                        if pg["id"] == "credential_exfil" and (
                                NEGATED.search(line[:match.start()]) or OWN_AUTH.search(line)):
                            is_info = True
                        if pg["id"] == "auth_bypass":
                            m0 = match.group(0).lower()
                            if m0.startswith("--") and not BYPASS_TOOL.search(line):
                                is_info = True
                            if GUARD_TEXT.search(line):
                                is_info = True
                        if is_info:
                            item["severity"] = "INFO"
                            info.append(item)
                        else:
                            findings.append(item)

    # Score (info items contribute 0 and are reported separately)
    total = 0
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        s = f["severity"].lower()
        total += SEVERITY_SCORE.get(s, 0)
        counts[f["severity"]] += 1
    total = min(total, 100)

    # Level is driven by the HIGHEST-severity real finding present (one credential-exfil
    # or pipe-to-shell is CRITICAL regardless of count), with risk_score as magnitude.
    # This replaces the additive-threshold scheme that only worked because benign noise
    # used to inflate every score.
    if counts["CRITICAL"]:
        level = "CRITICAL"
    elif counts["HIGH"]:
        level = "HIGH"
    elif counts["MEDIUM"]:
        level = "MEDIUM"
    elif counts["LOW"]:
        level = "LOW"
    else:
        level = "SAFE"

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: (sev_order.get(f["severity"], 99), f["line"]))

    parts = []
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts[s]:
            parts.append("%d %s" % (counts[s], s))

    info.sort(key=lambda f: f["line"])
    return {
        "risk_score": total,
        "risk_level": level,
        "findings": findings,
        "info": info,
        "summary": ", ".join(parts) if parts else "No issues found",
        "total_findings": len(findings),
        "info_count": len(info),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
         "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def _fetch(url):
    try:
        return urllib.request.urlopen(urllib.request.Request(
            url, headers={"User-Agent": "mcp-audit (github.com/eltociear)"}), timeout=15
        ).read().decode("utf-8", "replace")
    except Exception:
        return ""


def _report(label, text, as_json, out):
    r = scan(text[:400000])
    if as_json:
        out.append({"target": label, **r})
        return r
    icon = _ICON.get(r["risk_level"], "\u26AA")
    print(f"{icon} {label}  [{r['risk_level']}]  score={r['risk_score']}  "
          f"({r['total_findings']} findings, {r['info_count']} info)")
    for f in r["findings"]:
        print(f"    {f['severity']:8} {f['name']} (line {f['line']})")
        print(f"             {f['context']}")
    return r


CANDS = ["src/index.ts", "index.ts", "src/server.ts", "server.py", "src/main.py",
         "main.py", "src/index.js", "index.js", "README.md"]

# ── Entry-file selection (2026-11) ───────────────────────────────────────────
# Fixed paths missed most real servers (monorepos, packages/*/src, Go cmd/, Rust crates/).
# Pick from the repo's git tree instead: manifests, package.json main/bin targets (mapped
# from dist/ back to src/), and source files whose names say they define tools/servers.
CAP_FILES = 10
CAP_BYTES = 300_000
MANIFESTS = ("server.json", "manifest.json", "smithery.yaml", "package.json", "pyproject.toml", "README.md")
SKIP_PATH = re.compile(
    r"(?:^|/)(?:node_modules|dist|build|out|vendor|\.venv|venv|test|tests|__tests__|spec|examples?|"
    r"docs?|fixtures?|benchmarks?|\.github|coverage|target)/|\.(?:min|d|test|spec)\.\w+$|_test\.\w+$|"
    r"(?:^|/)test_\w+\.py$", re.I)
SRC_EXT = re.compile(r"\.(?:ts|mts|js|mjs|cjs|py|go|rs)$")
ENTRY_NAME = re.compile(r"(?:^|/)(?:index|server|main|app|cli|__main__|mcp|tools?|handlers?)\.\w+$|tool", re.I)


def _resolve(target, paths):
    target = re.sub(r"^\./", "", target or "")
    if not target:
        return []
    cands = [target]
    for a, b in (("dist/", "src/"), ("build/", "src/"), ("lib/", "src/")):
        if target.startswith(a):
            s = b + target[len(a):]
            cands += [re.sub(r"\.(?:c|m)?js$", e, s) for e in (".ts", ".mts", ".js")]
    return [c for c in cands if c in paths]


def pick_entry_files(paths, package_json=""):
    """paths: {path: size} of the repo's blobs. Returns up to CAP_FILES paths to scan."""
    chosen = []
    for m in MANIFESTS:
        for p in paths:
            if p.lower() == m.lower() or (m == "server.json" and p.endswith("/server.json") and p.count("/") == 1):
                chosen.append(p)
    if package_json:
        try:
            j = json.loads(package_json)
            bins = j.get("bin") or {}
            for t in [j.get("main")] + ([bins] if isinstance(bins, str) else list(bins.values())):
                chosen += _resolve(t, paths)
        except (ValueError, AttributeError):
            pass
    srcs = [p for p, sz in paths.items()
            if SRC_EXT.search(p) and not SKIP_PATH.search(p) and (sz or 0) < CAP_BYTES and ENTRY_NAME.search(p)]
    srcs.sort(key=lambda p: (p.count("/"), len(p)))
    out = []
    for p in chosen + srcs:
        if p not in out:
            out.append(p)
    return out[:CAP_FILES]


def _github_files(repo):
    """Tree-API selection (unauthenticated: 60 req/h; set GITHUB_TOKEN to raise it)."""
    import os
    hdr = {"User-Agent": "mcp-audit (github.com/eltociear)", "Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        hdr["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    try:
        tree = json.loads(urllib.request.urlopen(urllib.request.Request(
            f"https://api.github.com/repos/{repo}/git/trees/HEAD?recursive=1", headers=hdr), timeout=20).read())
        paths = {t["path"]: t.get("size", 0) for t in tree.get("tree", []) if t.get("type") == "blob"}
    except Exception:
        return None
    pkg = _fetch(f"https://raw.githubusercontent.com/{repo}/HEAD/package.json") if "package.json" in paths else ""
    return pick_entry_files(paths, pkg)


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    as_json = "--json" in args
    args = [a for a in args if a != "--json"]
    out, worst = [], "SAFE"
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "SAFE": 0}

    if args and args[0] == "--github":
        repo = args[1]
        got = 0
        files = _github_files(repo) or CANDS  # fixed paths only if the tree API is unavailable
        for f in files:
            t = _fetch(f"https://raw.githubusercontent.com/{repo}/HEAD/{f}")
            if len(t) >= 80:
                r = _report(f"{repo}/{f}", t, as_json, out)
                worst = r["risk_level"] if order[r["risk_level"]] > order[worst] else worst
                got += 1
        if not got:
            print(f"no fetchable entry files in {repo}")
    elif args and args[0] == "--text":
        r = _report("<text>", args[1] if len(args) > 1 else "", as_json, out)
        worst = r["risk_level"]
    else:
        for a in args:
            text = sys.stdin.read() if a == "-" else open(a, encoding="utf-8", errors="replace").read()
            r = _report(a, text, as_json, out)
            worst = r["risk_level"] if order[r["risk_level"]] > order[worst] else worst

    if as_json:
        print(json.dumps(out, indent=1))
    if order.get(worst, 0) >= order["HIGH"]:
        sys.exit(2)


if __name__ == "__main__":
    main()
