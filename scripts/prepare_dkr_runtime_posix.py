#!/usr/bin/env python3
"""POSIX port of Prepare-DKR-Runtime.ps1 for macOS and Linux hosts.

Prepares the DKR static recompilation without Windows or WSL:

  1. Checks host tools (git, cmake, ninja, make, a C++ compiler).
  2. Prepares the pinned dkr-decomp checkout (bootstrap_dependencies.py).
  3. Normalises and verifies the user-owned ROM (z64/v64/n64 byte orders,
     SHA-1 against the DKR US 1.0 fingerprint) into the decomp baseroms dir.
  4. Builds the matching decomp ELF with the decomp's own make pipeline,
     which already supports macOS (Darwin) and Linux natively.
  5. Resolves the recompilation entry function directly from the ELF with a
     built-in big-endian ELF32 reader - no mips binutils required.
  6. Prepares and patches N64ModernRuntime (+ pinned N64Recomp submodule)
     and optionally RT64 via the existing POSIX scripts.
  7. Builds N64RecompCLI and RSPRecomp with CMake + Ninja.
  8. Emits dkr.us.v77.generated.toml from the recomp policy JSON and runs
     N64Recomp to generate runtime-recomp/RecompiledFuncs.
  9. Regenerates the RSP translation units and builds the runtime probe.

No ROM or extracted asset is ever placed under source control paths that
DKR-R distributes; scan_for_game_assets.py still guards packaging.
"""

import argparse
import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

EXPECTED_SHA1 = "0cb115d8716dbbc2922fda38e533b9fe63bb9670"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DKR_SOURCE = PROJECT_ROOT / "extern" / "dkr-decomp"
RUNTIME_ROOT = PROJECT_ROOT / "runtime-recomp"
GENERATED_FUNCTIONS = RUNTIME_ROOT / "RecompiledFuncs"
LOG_DIRECTORY = PROJECT_ROOT / "build-logs"


def fail(message: str) -> "NoReturn":  # noqa: F821
    print(f"[ERROR] {message}", file=sys.stderr)
    raise SystemExit(1)


def step(message: str) -> None:
    print(f"\n==> {message}")


def ok(message: str) -> None:
    print(f"[OK] {message}")


def run(description, argv, cwd=None, env=None, log_path=None):
    print(f"-- {description}")
    if log_path:
        with open(log_path, "ab") as log:
            log.write(f"\n$ {' '.join(map(str, argv))}\n".encode())
            proc = subprocess.run(list(map(str, argv)), cwd=cwd, env=env,
                                  stdout=log, stderr=subprocess.STDOUT)
    else:
        proc = subprocess.run(list(map(str, argv)), cwd=cwd, env=env)
    if proc.returncode != 0:
        extra = f" Log: {log_path}" if log_path else ""
        fail(f"{description} failed with exit code {proc.returncode}.{extra}")


# --------------------------------------------------------------------------
# ROM normalisation
# --------------------------------------------------------------------------

def normalise_rom(source: Path, destination: Path) -> bytes:
    data = bytearray(source.read_bytes())
    if len(data) < 0x40:
        fail("The selected ROM is too small to contain an N64 header.")
    magic = bytes(data[:4]).hex()
    if magic == "80371240":
        ok("ROM byte order: z64 / big-endian")
    elif magic == "37804012":
        ok("ROM byte order: v64 / byte-swapped; normalising locally")
        data[0::2], data[1::2] = data[1::2], data[0::2]
    elif magic == "40123780":
        ok("ROM byte order: n64 / little-endian; normalising locally")
        view = bytearray(len(data))
        view[0::4], view[1::4], view[2::4], view[3::4] = (
            data[3::4], data[2::4], data[1::4], data[0::4])
        data = view
    else:
        fail(f"The selected file does not have a recognised N64 ROM byte order (magic {magic}).")
    digest = hashlib.sha1(bytes(data)).hexdigest()
    if digest != EXPECTED_SHA1:
        fail(f"The normalised ROM SHA-1 is {digest}, but DKR US 1.0 requires {EXPECTED_SHA1}.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(bytes(data))
    ok(f"Canonical local build ROM written to: {destination}")
    return bytes(data)


# --------------------------------------------------------------------------
# Minimal big-endian ELF32 reader (replaces mips-linux-gnu-nm/readelf)
# --------------------------------------------------------------------------

def read_elf_symbols(elf_path: Path):
    blob = elf_path.read_bytes()
    if blob[:4] != b"\x7fELF":
        fail(f"Not an ELF file: {elf_path}")
    ei_class, ei_data = blob[4], blob[5]
    if ei_class != 1 or ei_data != 2:
        fail("The DKR ELF is expected to be 32-bit big-endian (MIPS).")

    def u16(off):
        return struct.unpack_from(">H", blob, off)[0]

    def u32(off):
        return struct.unpack_from(">I", blob, off)[0]

    e_shoff, e_shentsize, e_shnum, e_shstrndx = (
        u32(0x20), u16(0x2E), u16(0x30), u16(0x32))

    sections = []
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        sections.append({
            "name_off": u32(base + 0x00),
            "type": u32(base + 0x04),
            "flags": u32(base + 0x08),
            "addr": u32(base + 0x0C),
            "offset": u32(base + 0x10),
            "size": u32(base + 0x14),
            "link": u32(base + 0x18),
        })

    shstr = sections[e_shstrndx]

    def section_name(sec):
        start = shstr["offset"] + sec["name_off"]
        end = blob.index(b"\x00", start)
        return blob[start:end].decode("ascii", "replace")

    names = [section_name(s) for s in sections]
    has_mdebug = ".mdebug" in names

    symbols = []
    for idx, sec in enumerate(sections):
        if sec["type"] != 2:  # SHT_SYMTAB
            continue
        strtab = sections[sec["link"]]
        for off in range(sec["offset"], sec["offset"] + sec["size"], 16):
            st_name, st_value = u32(off), u32(off + 4)
            st_info = blob[off + 12]
            st_shndx = u16(off + 14)
            if st_name == 0:
                continue
            nstart = strtab["offset"] + st_name
            nend = blob.index(b"\x00", nstart)
            symname = blob[nstart:nend].decode("ascii", "replace")
            executable = False
            if 0 < st_shndx < len(sections):
                executable = bool(sections[st_shndx]["flags"] & 0x4)  # SHF_EXECINSTR
            symbols.append({
                "name": symname,
                "value": st_value,
                "type": st_info & 0xF,
                "executable": executable,
            })
    return symbols, has_mdebug


def resolve_entrypoint(elf_path: Path, rom_header_entrypoint: int):
    symbols, has_mdebug = read_elf_symbols(elf_path)
    mainproc = next((s for s in symbols if s["name"] == "mainproc"), None)
    header_sym = next(
        (s for s in symbols
         if s["value"] == rom_header_entrypoint and s["executable"]),
        None)

    # DKR's decomp documents mainproc as the function run after IPL3 has
    # completed. Prefer that real function symbol over the raw ROM header PC.
    if mainproc is not None:
        selected, symbol = mainproc["value"], "mainproc"
    elif header_sym is not None:
        selected, symbol = header_sym["value"], header_sym["name"]
    else:
        fail("The DKR ELF contains neither the mainproc symbol nor a text "
             f"symbol at the ROM header entry point 0x{rom_header_entrypoint:08X}.")
    if selected & 3:
        fail(f"Resolved DKR entrypoint {symbol} at 0x{selected:08X}, but it is not word-aligned.")
    ok(f"Static recompilation entry function: {symbol} at 0x{selected:08X}")
    ok(f"ELF .mdebug metadata available: {has_mdebug}")
    return f"0x{selected:08X}", symbol, has_mdebug


# --------------------------------------------------------------------------
# TOML generation (faithful port of the PowerShell emitter)
# --------------------------------------------------------------------------

def emit_generated_toml(policy_path: Path, toml_path: Path, entry_text: str,
                        use_mdebug: bool, elf_path: Path, rom_path: Path):
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    if int(policy.get("schemaVersion", -1)) != 1:
        fail("Unsupported DKR recompilation policy schema.")

    def quoted_names(key):
        return ", ".join('"' + str(e["name"]).replace('"', '\\"') + '"'
                         for e in policy.get(key, []))

    function_sizes = ", ".join(
        f'{{ name = "{e["name"]}", size = {e["size"]} }}'
        for e in policy.get("functionSizes", []))
    manual_functions = ", ".join(
        f'{{ name = "{e["name"]}", section = "{e["section"]}", '
        f'vram = {e["vram"]}, size = {e["size"]} }}'
        for e in policy.get("manualFunctions", []))
    instruction_patches = "\n\n".join(
        f'[[patches.instruction]]\nfunc = "{e["function"]}"\n'
        f'vram = {e["vram"]}\nvalue = {e["value"]}'
        for e in policy.get("instructionPatches", []))
    function_hooks = "\n\n".join(
        '[[patches.hook]]\nfunc = "{f}"\nbefore_vram = {v}\ntext = "{t}"'.format(
            f=e["function"], v=e["beforeVram"],
            t=str(e["text"]).replace("\\", "\\\\").replace('"', '\\"'))
        for e in policy.get("functionHooks", []))

    content = f"""# Generated by prepare_dkr_runtime_posix.py.
# This is the first-pass DKR CPU recompilation configuration. DKR-specific
# stubs, manual boundaries and instruction patches will be added from the
# emitted diagnostics.
[input]
entrypoint = {entry_text}
use_mdebug = {str(use_mdebug).lower()}
elf_path = "{elf_path.as_posix()}"
rom_file_path = "{rom_path.as_posix()}"
output_func_path = "{GENERATED_FUNCTIONS.as_posix()}"
manual_funcs = [{manual_functions}]
function_sizes = [{function_sizes}]

[patches]
stubs = [{quoted_names("stubs")}]
renamed = [{quoted_names("renamed")}]
ignored = [{quoted_names("ignored")}]

# BEGIN DKR_INSTRUCTION_PATCHES
{instruction_patches}
# END DKR_INSTRUCTION_PATCHES

# BEGIN DKR_FUNCTION_HOOKS
{function_hooks}
# END DKR_FUNCTION_HOOKS
"""
    toml_path.write_text(content, encoding="utf-8")  # BOM-free by default
    ok(f"Recompilation configuration written: {toml_path}")


# --------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------

def find_executable(root: Path, name: str) -> Path:
    matches = [p for p in root.rglob(name)
               if p.is_file() and os.access(p, os.X_OK)]
    if not matches:
        fail(f"{name} was not found under {root} after the build.")
    return matches[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rom", type=Path,
                        help="Path to your Diddy Kong Racing US 1.0 ROM "
                             "(z64/v64/n64). Optional if the canonical build "
                             "ROM has already been prepared.")
    parser.add_argument("--jobs", type=int, default=0)
    parser.add_argument("--skip-decomp-build", action="store_true",
                        help="Reuse an existing extern/dkr-decomp/build ELF.")
    parser.add_argument("--skip-recompile", action="store_true")
    parser.add_argument("--skip-probe", action="store_true")
    parser.add_argument("--no-renderer", action="store_true",
                        help="Skip the RT64 checkout and renderer probe.")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    jobs = args.jobs if args.jobs > 0 else max(2, (os.cpu_count() or 2) - 1)
    LOG_DIRECTORY.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = LOG_DIRECTORY / f"prepare-dkr-runtime-posix-{timestamp}.log"

    print("DKR-R - decomp ELF and static-recompilation preparation (POSIX)")
    print(f"Project: {PROJECT_ROOT}")
    print(f"Host: {platform.system()} {platform.machine()}")
    print(f"Log: {log_path}")

    for tool in ("git", "cmake", "ninja", "make", "c++"):
        if shutil.which(tool) is None:
            fail(f"Missing required tool: {tool}. "
                 "macOS: xcode-select --install && brew install cmake ninja. "
                 "Linux: apt install build-essential cmake ninja-build.")

    if platform.system() == "Darwin" and platform.machine() == "arm64":
        # The decomp's matching IDO compilers ship as x86_64 macOS binaries
        # and run under Rosetta 2 on Apple Silicon.
        rosetta = subprocess.run(["arch", "-x86_64", "/usr/bin/true"],
                                 capture_output=True)
        if rosetta.returncode != 0:
            fail("Rosetta 2 is required to run the decomp's IDO compiler "
                 "binaries on Apple Silicon. Install it with: "
                 "softwareupdate --install-rosetta --agree-to-license")
        ok("Rosetta 2 is available for the x86_64 IDO compiler binaries.")

    step("Preparing the pinned DKR decomp checkout")
    bootstrap = [sys.executable, PROJECT_ROOT / "scripts" / "bootstrap_dependencies.py",
                 "--only", "dkr-decomp"]
    if args.force:
        bootstrap.append("--force")
    run("Prepare pinned dkr-decomp", bootstrap, cwd=PROJECT_ROOT)

    step("Locating and normalising the user-owned ROM")
    canonical_rom = DKR_SOURCE / "baseroms" / "dkr.us.v77.z64"
    if args.rom:
        rom_bytes = normalise_rom(args.rom.expanduser().resolve(), canonical_rom)
    elif canonical_rom.is_file():
        rom_bytes = canonical_rom.read_bytes()
        digest = hashlib.sha1(rom_bytes).hexdigest()
        if digest != EXPECTED_SHA1:
            fail(f"The prepared ROM at {canonical_rom} does not match DKR US 1.0.")
        ok(f"Using the previously prepared canonical ROM: {canonical_rom}")
    else:
        fail("No ROM was provided. Rerun with --rom /path/to/your/dkr.us.z64 "
             "(your own legally obtained US 1.0 dump).")
    rom_header_entrypoint = struct.unpack_from(">I", rom_bytes, 8)[0]
    ok(f"ROM header entry point: 0x{rom_header_entrypoint:08X}")

    elf_path = DKR_SOURCE / "build" / "dkr.us.v77.elf"
    built_rom_path = DKR_SOURCE / "build" / "dkr.us.v77.z64"

    if not args.skip_decomp_build:
        step("Building the completed DKR decomp ELF natively")
        run("Initialise decomp submodules",
            ["git", "-C", DKR_SOURCE, "submodule", "update", "--init", "--recursive"],
            log_path=log_path)
        venv_python = DKR_SOURCE / ".venv" / "bin" / "python3"
        needs_setup = not venv_python.exists() or subprocess.run(
            [venv_python, "-c", "import splat"], capture_output=True).returncode != 0
        if needs_setup:
            print("[INFO] The DKR Python/tool environment is incomplete; running make setup.")
            run("make setup", ["make", "setup"], cwd=DKR_SOURCE, log_path=log_path)
        if subprocess.run([venv_python, "-c", "import splat"],
                          capture_output=True).returncode != 0:
            fail("DKR make setup completed, but the splat module is still "
                 "unavailable in .venv. Remove extern/dkr-decomp/.venv and retry.")
        run("make extract", ["make", "extract"], cwd=DKR_SOURCE, log_path=log_path)
        run(f"make -j{jobs}", ["make", f"-j{jobs}"], cwd=DKR_SOURCE, log_path=log_path)

    if not elf_path.is_file():
        fail(f"The DKR build did not produce the expected ELF: {elf_path}")
    if not built_rom_path.is_file():
        fail(f"The DKR build did not produce the expected ROM image: {built_rom_path}")
    ok(f"Matching DKR ELF: {elf_path}")

    step("Resolving the DKR static-recompilation entry function")
    entry_text, entry_symbol, use_mdebug = resolve_entrypoint(
        elf_path, rom_header_entrypoint)

    step("Preparing the static recompilation tool and runtime sources")
    lock = json.loads((PROJECT_ROOT / "dependencies.lock.json").read_text())
    pinned = {d["name"]: d for d in lock["dependencies"]}

    def dep_ready(name):
        entry = pinned[name]
        dest = PROJECT_ROOT / entry["destination"]
        if not (dest / ".git").exists():
            return False
        head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"],
                              capture_output=True, text=True).stdout.strip()
        return head == entry["commit"]

    wanted = ["n64-modern-runtime"] + ([] if args.no_renderer else ["rt64"])
    todo = [n for n in wanted if args.force or not dep_ready(n)]
    if todo:
        deps = [sys.executable, PROJECT_ROOT / "scripts" / "bootstrap_dependencies.py"]
        for n in todo:
            deps += ["--only", n]
        if args.force:
            deps.append("--force")
        run("Prepare pinned runtime dependencies", deps, cwd=PROJECT_ROOT)
    else:
        ok("Pinned runtime dependencies already at their locked commits.")
    run("Apply pinned dependency patches",
        ["bash", PROJECT_ROOT / "scripts" / "apply-dependency-patches.sh"],
        cwd=PROJECT_ROOT)

    n64recomp_src = PROJECT_ROOT / "extern" / "n64-modern-runtime" / "N64Recomp"
    tool_build = PROJECT_ROOT / "build" / "runtime-tools" / "n64recomp"
    run("Configure N64Recomp tools",
        ["cmake", "-S", n64recomp_src, "-B", tool_build, "-G", "Ninja",
         "-DCMAKE_BUILD_TYPE=Release"], log_path=log_path)
    run("Build N64RecompCLI and RSPRecomp",
        ["cmake", "--build", tool_build, "--target", "N64RecompCLI", "RSPRecomp",
         "--parallel", str(jobs)], log_path=log_path)
    recompiler = find_executable(tool_build, "N64Recomp")
    rsp_recompiler = find_executable(tool_build, "RSPRecomp")
    ok(f"N64Recomp executable: {recompiler}")
    ok(f"RSPRecomp executable: {rsp_recompiler}")

    if args.force and GENERATED_FUNCTIONS.exists():
        shutil.rmtree(GENERATED_FUNCTIONS)
    GENERATED_FUNCTIONS.mkdir(parents=True, exist_ok=True)

    toml_path = RUNTIME_ROOT / "dkr.us.v77.generated.toml"
    emit_generated_toml(RUNTIME_ROOT / "dkr.us.v77.recomp-policy.json",
                        toml_path, entry_text, use_mdebug, elf_path,
                        built_rom_path)

    if not args.skip_recompile:
        step("Generating the native C translation of DKR")
        run("N64Recomp", [recompiler, toml_path], cwd=RUNTIME_ROOT)
        step("Generating the DKR RSP translation units")
        rsp_dir = RUNTIME_ROOT / "rsp"
        (RUNTIME_ROOT / "RecompiledRSP").mkdir(parents=True, exist_ok=True)
        for config in sorted(rsp_dir.glob("*.toml")):
            run(f"RSPRecomp {config.name}", [rsp_recompiler, config], cwd=rsp_dir)

    function_files = [p for p in GENERATED_FUNCTIONS.rglob("*")
                      if p.suffix in (".c", ".cpp")]

    probe_built = False
    if not args.skip_probe:
        if not function_files:
            fail("No generated CPU translation files were found, so the "
                 "runtime compilation probe cannot be built.")
        step("Compiling generated DKR CPU code against N64ModernRuntime")
        probe_build = PROJECT_ROOT / "build" / "dkr-runtime-probe"
        renderer = "OFF" if args.no_renderer else "ON"
        run("Configure runtime probe",
            ["cmake", "-S", RUNTIME_ROOT, "-B", probe_build, "-G", "Ninja",
             "-DCMAKE_BUILD_TYPE=Release", f"-DDKRPORT_ROOT={PROJECT_ROOT}",
             "-DDKR_RUNTIME_BUILD_GENERATED=ON",
             f"-DDKR_RUNTIME_BUILD_RT64={renderer}"], log_path=log_path)
        run("Build runtime probe",
            ["cmake", "--build", probe_build, "--parallel", str(jobs)],
            log_path=log_path)
        probe = find_executable(probe_build, "DKRRuntimeProbe")
        run("Run runtime probe", [probe])
        probe_built = True
        ok(f"Runtime compilation probe: {probe}")

    state = {
        "schemaVersion": 2,
        "preparedUtc": datetime.now(timezone.utc).isoformat(),
        "preparedBy": "prepare_dkr_runtime_posix.py",
        "host": f"{platform.system()} {platform.machine()}",
        "sourceRomSha1": EXPECTED_SHA1,
        "romHeaderEntrypoint": f"0x{rom_header_entrypoint:08X}",
        "recompEntrypoint": entry_text,
        "recompEntrypointSymbol": entry_symbol,
        "useMdebug": use_mdebug,
        "dkrElf": str(elf_path),
        "generatedFunctionFiles": len(function_files),
        "n64RecompExecutable": str(recompiler),
        "rspRecompExecutable": str(rsp_recompiler),
        "runtimeProbeBuilt": probe_built,
        "rt64BuildRequested": not args.no_renderer,
    }
    (RUNTIME_ROOT / "resolved-runtime-dependencies.json").write_text(
        json.dumps(state, indent=2) + "\n", encoding="utf-8")

    print()
    ok("DKR runtime preparation completed on this POSIX host.")
    print(f"Generated function files: {len(function_files)}")
    if platform.system() == "Darwin":
        print("Next: ./Build-macOS.sh to produce the signed DKR-R.app bundle.")
    else:
        print("Next: ./Build-Linux.sh to produce the AppImage.")
    print("No ROM or extracted game asset is added to source control or the "
          "distributable archive.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
