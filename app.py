#!/usr/bin/env python3
"""Fixed-scope dictionary audit adapter for authorized password-hash reviews."""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import tempfile

INPUT_ROOT = pathlib.Path("/workspace/inputs")
HASHCAT_ROOT = pathlib.Path("/opt/hashcat")
HASHCAT_BINARY = HASHCAT_ROOT / "hashcat.bin"
MAX_HASH_FILE_BYTES = 10 * 1024 * 1024
MAX_WORDLIST_BYTES = 1024 * 1024 * 1024
MAX_HASHES = 10_000
MAX_CANDIDATES = 10_000_000
MAX_CANDIDATE_BYTES = 256
ALLOWED_MODES = {
    "0": ("MD5", 32),
    "100": ("SHA-1", 40),
    "1000": ("NTLM", 32),
    "1400": ("SHA-256", 64),
    "1700": ("SHA-512", 128),
}
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class AuditInputError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class AuditExecutionError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def validate_mounted_file(value: str, label: str, max_bytes: int, input_root: pathlib.Path | None = None) -> pathlib.Path:
    root = (input_root or INPUT_ROOT).resolve(strict=True)
    supplied = pathlib.Path(value)
    if supplied.is_symlink():
        raise AuditInputError("input_symlink_rejected", f"{label} must not be a symbolic link")
    path = supplied.resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file():
        raise AuditInputError("input_path_rejected", f"{label} must be a regular file in the approved input mount")
    if path.stat().st_size > max_bytes:
        raise AuditInputError("input_size_limit", f"{label} exceeds its approved size limit")
    return path


def validate_hashes(path: pathlib.Path, mode: str) -> int:
    if mode not in ALLOWED_MODES:
        raise AuditInputError("hash_mode_rejected", "Hash mode is not approved")
    _name, expected_length = ALLOWED_MODES[mode]
    count = 0
    seen: set[str] = set()
    with path.open("r", encoding="ascii", errors="strict", newline=None) as source:
        for count, raw in enumerate(source, start=1):
            value = raw.rstrip("\r\n")
            if count > MAX_HASHES:
                raise AuditInputError("hash_count_limit", f"Hash file exceeds the {MAX_HASHES}-hash limit")
            if value != value.strip() or len(value) != expected_length or not HEX_RE.fullmatch(value):
                raise AuditInputError("hash_format_rejected", f"Hash line {count} is not valid {ALLOWED_MODES[mode][0]} hexadecimal")
            normalized = value.lower()
            if normalized in seen:
                raise AuditInputError("duplicate_hash_rejected", f"Hash line {count} duplicates an earlier hash")
            seen.add(normalized)
    if count == 0:
        raise AuditInputError("hash_file_empty", "Hash file is empty")
    return count


def validate_wordlist(path: pathlib.Path) -> int:
    count = 0
    with path.open("rb") as source:
        for count, raw in enumerate(source, start=1):
            candidate = raw.rstrip(b"\r\n")
            if count > MAX_CANDIDATES:
                raise AuditInputError("candidate_count_limit", f"Wordlist exceeds the {MAX_CANDIDATES}-candidate limit")
            if len(candidate) > MAX_CANDIDATE_BYTES:
                raise AuditInputError("candidate_length_limit", f"Wordlist candidate {count} exceeds {MAX_CANDIDATE_BYTES} bytes")
            if b"\x00" in candidate:
                raise AuditInputError("candidate_nul_rejected", f"Wordlist candidate {count} contains a NUL byte")
    if count == 0:
        raise AuditInputError("wordlist_empty", "Wordlist is empty")
    return count


def build_command(mode: str, hashes: pathlib.Path, wordlist: pathlib.Path, outfile: pathlib.Path) -> list[str]:
    return [
        str(HASHCAT_BINARY),
        "--attack-mode", "0",
        "--hash-type", mode,
        "--quiet",
        "--potfile-disable",
        "--restore-disable",
        "--logfile-disable",
        "--wordlist-autohex-disable",
        "--hwmon-disable",
        "--outfile", str(outfile),
        "--outfile-format", "1,3",
        "--separator", ":",
        str(hashes),
        str(wordlist),
    ]


def parse_results(outfile: pathlib.Path) -> list[dict[str, str | None]]:
    if not outfile.exists():
        return []
    results = []
    try:
        lines = outfile.read_text(encoding="ascii").splitlines()
    except UnicodeError as error:
        raise AuditExecutionError("result_format_error") from error
    for raw in lines:
        try:
            hash_value, plain_hex = raw.rsplit(":", 1)
            if not hash_value or not HEX_RE.fullmatch(hash_value):
                raise ValueError("invalid hash field")
            if len(plain_hex) % 2 or (plain_hex and not HEX_RE.fullmatch(plain_hex)):
                raise ValueError("invalid hexadecimal plaintext field")
            plain_bytes = bytes.fromhex(plain_hex)
        except ValueError as error:
            raise AuditExecutionError("result_format_error") from error
        try:
            plain_utf8 = plain_bytes.decode("utf-8")
        except UnicodeDecodeError:
            plain_utf8 = None
        results.append({"hash": hash_value, "password_utf8": plain_utf8, "password_hex": plain_hex.lower()})
    return results


def classify_hashcat_failure(returncode: int, diagnostic: bytes) -> str:
    lowered = diagnostic.lower()
    if b"nvidia rtc" in lowered or b"cuda sdk toolkit" in lowered or b"nvrtc" in lowered:
        return "gpu_toolkit_unavailable"
    if b"no opencl, hip or cuda compatible platform" in lowered or b"cuinit" in lowered:
        return "gpu_runtime_unavailable"
    if returncode in {2, 3, 4}:
        return "hashcat_interrupted"
    return "hashcat_execution_failed"


def run(mode: str, hashes_value: str, wordlist_value: str) -> dict[str, object]:
    hashes = validate_mounted_file(hashes_value, "Hash file", MAX_HASH_FILE_BYTES)
    wordlist = validate_mounted_file(wordlist_value, "Wordlist", MAX_WORDLIST_BYTES)
    hash_count = validate_hashes(hashes, mode)
    candidate_count = validate_wordlist(wordlist)
    with tempfile.TemporaryDirectory(prefix="estoc-hash-audit-") as raw:
        outfile = pathlib.Path(raw) / "recovered.txt"
        command = build_command(mode, hashes, wordlist, outfile)
        completed = subprocess.run(command, cwd=HASHCAT_ROOT, capture_output=True, check=False)
        if completed.returncode not in {0, 1}:
            raise AuditExecutionError(classify_hashcat_failure(completed.returncode, completed.stderr))
        results = parse_results(outfile)
    return {
        "status": "matches_found" if results else "exhausted",
        "hash_mode": mode,
        "hash_name": ALLOWED_MODES[mode][0],
        "hash_count": hash_count,
        "candidate_count": candidate_count,
        "recovered_count": len(results),
        "results": results,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print("Expected exactly: HASH_MODE HASH_FILE WORDLIST_FILE", file=sys.stderr)
        return 2
    try:
        result = run(argv[1], argv[2], argv[3])
    except (AuditInputError, AuditExecutionError) as error:
        print(f"ESTOC_SAFE_ERROR:{error.code}", file=sys.stderr)
        return 2
    except (OSError, RuntimeError, UnicodeError):
        print("ESTOC_SAFE_ERROR:adapter_internal_error", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
