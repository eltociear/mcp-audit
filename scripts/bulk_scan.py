#!/usr/bin/env python3
"""Bulk-scan a list of GitHub repos with mcp_audit.scan().

Picks each repo's *real* entry files from its git tree (one `gh api` call per repo) with the
same selection `mcp_audit.py --github` uses (mcp_audit.pick_entry_files): manifests,
package.json main/bin targets, and source files that define tools/servers. File bodies come
from raw.githubusercontent.com. Needs the `gh` CLI. Network errors are retried, and a repo
that still fails is left unrecorded, so re-running the same command resumes it.

  python scripts/bulk_scan.py repos.json out.jsonl [--workers 12]
Resumable: repos already in out.jsonl are skipped.
"""
import concurrent.futures as cf
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from mcp_audit import CAP_BYTES, pick_entry_files, scan  # noqa: E402

class NetErr(Exception):
    pass


NET = re.compile(r"unreachable|dial tcp|timeout|timed out|EOF|connection|no such host|rate limit|50[234]", re.I)


def gh(path):
    for a in range(5):
        try:
            r = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            time.sleep(5 * (a + 1))
            continue
        if r.returncode and NET.search(r.stderr):
            time.sleep(min(60, 5 * 2 ** a) if "rate limit" not in r.stderr.lower() else 300)
            continue
        break
    else:
        raise NetErr(path)
    if r.returncode:
        return None
    try:
        return json.loads(r.stdout)
    except ValueError:
        return None


def raw(repo, ref, path):
    url = f"https://raw.githubusercontent.com/{urllib.parse.quote(repo)}/{urllib.parse.quote(ref)}/{urllib.parse.quote(path)}"
    for a in range(4):
        try:
            return urllib.request.urlopen(urllib.request.Request(
                url, headers={"User-Agent": "mcp-audit-bulk"}), timeout=10).read(CAP_BYTES).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ""
        except Exception:
            pass
        time.sleep(3 * (a + 1))
    raise NetErr(url)


def pick(repo, ref, tree):
    paths = {t["path"]: t.get("size", 0) for t in tree if t.get("type") == "blob"}
    pkg = raw(repo, ref, "package.json") if "package.json" in paths else ""
    return pick_entry_files(paths, pkg), pkg


def scan_repo(repo):
    # One API call per repo: the recursive tree at HEAD (404 -> deleted/private/empty).
    ref = "HEAD"
    t = gh(f"repos/{repo}/git/trees/{ref}?recursive=1")
    if not t or "tree" not in t:
        return {"repo": repo, "status": "unfetchable"}
    meta = {"full_name": repo}
    files, pkg = pick(meta["full_name"], ref, t["tree"])
    res = []
    with cf.ThreadPoolExecutor(6) as ex:
        bodies = list(ex.map(lambda f: pkg if f == "package.json" and pkg else raw(meta["full_name"], ref, f), files))
    for f, body in zip(files, bodies):
        if len(body) < 40:
            continue
        r = scan(body)
        res.append({"file": f, "level": r["risk_level"], "score": r["risk_score"],
                    "findings": [{k: x[k] for k in ("severity", "id", "line", "context")} for x in r["findings"]],
                    "info_ids": sorted({x["id"] for x in r["info"]})})
    src = [r for r in res if r["file"] != "README.md"]
    return {"repo": meta["full_name"], "status": "scanned" if src else "no_source",
            "files": res}


def main():
    src, dst = sys.argv[1], sys.argv[2]
    workers = int(sys.argv[sys.argv.index("--workers") + 1]) if "--workers" in sys.argv else 12
    repos = json.load(open(src))
    done = set()
    if os.path.exists(dst):
        for line in open(dst):
            try:
                done.add(json.loads(line)["_in"])
            except Exception:
                pass
    todo = [r for r in repos if r not in done]
    print(f"{len(repos)} repos, {len(todo)} to scan", file=sys.stderr)
    neterr = 0
    with open(dst, "a") as out, cf.ThreadPoolExecutor(workers) as ex:
        futs = {ex.submit(scan_repo, r): r for r in todo}
        for i, fu in enumerate(cf.as_completed(futs), 1):
            try:
                row = fu.result()
            except NetErr:
                neterr += 1  # not recorded -> retried on the next (resumed) run
                continue
            except Exception as e:
                row = {"repo": futs[fu], "status": "error", "error": str(e)[:200]}
            row["_in"] = futs[fu]
            out.write(json.dumps(row) + "\n")
            out.flush()
            if i % 50 == 0:
                print(f"{i}/{len(todo)} neterr={neterr}", file=sys.stderr, flush=True)
    print(f"DONE neterr={neterr}", file=sys.stderr)


if __name__ == "__main__":
    main()
