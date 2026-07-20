# ESTOC Intel Hash Audit Adapter

A deliberately constrained adapter for authorized password-hash strength audits in the ESTOC Intel Operations Console. It runs a fixed Hashcat straight/dictionary audit against files supplied through the console's ephemeral, read-only input mount.

Use this software only with hashes, candidate dictionaries, systems, and accounts you own or are explicitly authorized to assess.

## Fixed security boundary

- Dictionary/straight attack mode (`--attack-mode 0`) only.
- Approved unsalted modes only: MD5 (`0`), SHA-1 (`100`), NTLM (`1000`), SHA-256 (`1400`), and SHA-512 (`1700`).
- Exactly three runtime inputs: one approved mode, one hash file, and one wordlist file.
- Hash and wordlist paths must resolve to regular files inside `/workspace/inputs`.
- At most 10,000 unique hashes and 10,000,000 wordlist candidates.
- Hash syntax and length are validated for the selected mode before execution.
- Candidates are limited to 256 bytes and may not contain NUL bytes.
- No shell, pseudo-terminal, masks, rules, combinators, arbitrary flags, sessions, restores, potfiles, tunnels, credentials, or runtime network access.
- Hashcat output uses hex-encoded plaintext records. The adapter emits sensitive JSON only to standard output so the console can stage it privately and require **Save securely**.

The adapter never modifies either input file. Temporary recovery output exists only within the isolated task sandbox.

## Approved console entrypoint

The only supported non-interactive command is:

```json
["python3", "/opt/estoc/app.py", "{{hash_mode}}", "{{hashes_file}}", "{{wordlist_file}}"]
```

Manifest guidance:

- `hash_mode`: required non-sensitive `text` input.
- `hashes_file`: required sensitive `r2_object` input.
- `wordlist_file`: required sensitive `r2_object` input.
- output: sensitive JSON.
- resource class: `gpu`, using one `L4`.
- workdir: `/opt/hashcat`.
- runtime network: blocked with an empty allowlist.
- sensitive-file confirmation: required.
- Dockerfile build: requires explicit build-time network approval for `registry-1.docker.io`, `archive.ubuntu.com`, `security.ubuntu.com`, and `hashcat.net`.

The image uses the official Hashcat 7.1.2 binary release and verifies SHA-256 `80db0316387794ce9d14ed376da75b8a7742972485b45db790f5f8260307ff98` before extraction. Hashcat is distributed under the MIT License by its upstream project: <https://github.com/hashcat/hashcat>.

## Local tests

The tests exercise the wrapper without running Hashcat or requiring a GPU:

```text
python -m unittest discover -s tests -v
```
