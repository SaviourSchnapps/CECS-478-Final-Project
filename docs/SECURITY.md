# Security

## Invariants

Properties the system enforces. Violation = bug.

1. **No raw packet bytes on disk after analysis.** Zeek reads pcaps read-only; the analyzer never opens them.
2. **No process runs as root.** Both containers run as UID 1000.
3. **No Linux capabilities.** `cap_drop: [ALL]` on both services.
4. **No network egress.** No networks attached, no ports exposed.
5. **Read-only filesystem.** `read_only: true`; only `tmpfs:/tmp` and the explicit `:rw` output mount are writable.
6. **No new privileges.** `no-new-privileges:true` on both services.
7. **Bounded input.** Parser rejects lines >64 KB, malformed JSON, invalid IPs, bad timestamps.
8. **Per-source rate limit.** Token bucket caps alerts per source IP (default 50/s, burst floor 10).

## Threat model

| Adversary | Mitigation |
|---|---|
| Malformed/oversize input | Strict parser validation |
| Compromised pcap source | Read-only mount; analyzer treats Zeek output as untrusted |
| Single noisy source flooding the pipeline | Token-bucket rate limiter |
| Container RCE via Zeek bug | Dropped caps + no network + read-only FS + no-new-privileges |

**Out of scope:** root-on-host attackers (container isolation isn't a boundary against them), sub-threshold evaders (detection is heuristic).
