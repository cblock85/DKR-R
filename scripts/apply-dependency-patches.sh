#!/usr/bin/env bash
set -euo pipefail
project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$project_root/patches/manifest.json"
python3 - "$project_root" "$manifest" <<'PY'
import hashlib, json, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1]); manifest_path = pathlib.Path(sys.argv[2])
data = json.loads(manifest_path.read_text(encoding="utf-8"))
if data.get("schemaVersion") != 1:
    raise SystemExit("Unsupported patch manifest schema")
stamp_path = root / "extern" / ".applied-patches.json"
try:
    stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
except Exception:
    stamp = {}
new_stamp = {}
for dependency in data["dependencies"]:
    name = dependency["name"]
    repo = root / dependency["repositoryPath"]
    commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    if commit != dependency["expectedCommit"]:
        raise SystemExit(f"{name} commit mismatch: expected {dependency['expectedCommit']}, got {commit}")
    digests = []
    for entry in dependency["patches"]:
        patch = root / entry["path"]
        digest = hashlib.sha256(patch.read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            raise SystemExit(f"Patch checksum mismatch: {entry['path']}")
        digests.append(digest)
    state = {"commit": commit, "patches": digests}
    if stamp.get(name) == state:
        print(f"[OK] {name}: patch series already applied (stamp match)")
        new_stamp[name] = state
        continue
    changes = subprocess.check_output(["git", "-C", str(repo), "status", "--short", "--untracked-files=no", "--ignore-submodules=dirty"], text=True)
    if changes.strip():
        raise SystemExit(
            f"{name} has local changes but no matching patch stamp.\n"
            f"If these are only previously applied manifest patches, reset with:\n"
            f"  git -C {repo} checkout -- .\nthen rerun.\n{changes}")
    for entry in dependency["patches"]:
        patch = root / entry["path"]
        subprocess.run(["git", "-C", str(repo), "apply", "--check", str(patch)], check=True)
        subprocess.run(["git", "-C", str(repo), "apply", str(patch)], check=True)
        print(f"[OK] {name}: {entry['path']} (applied)")
    new_stamp[name] = state
stamp_path.write_text(json.dumps(new_stamp, indent=2) + "\n", encoding="utf-8")
print("[OK] Patch stamp updated:", stamp_path)
PY
