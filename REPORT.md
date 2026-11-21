# Plex2Shell to Root: Incident Analysis

Published 21 November 2026

Author and responsible: Hugo L. Espuny. Contact: [github.com/fakehec](https://github.com/fakehec)

## Summary

An Internet-facing Linux server running an unpatched Plex Media Server was compromised to root in October 2026 by an automated cryptomining operation. Initial access used the public Plex2Shell exploit chain; privilege escalation used the xfrm/ESP variant of Dirty Frag (CVE-2026-43284) against a kernel build that predated the fix.

The escalation was first treated as an unproven theory because no exploit artifact had been found. This analysis shows the proof was in the quarantined loader all along, and recovers the complete toolkit.

| Finding | Basis | Confidence |
| --- | --- | --- |
| Initial access through Plex2Shell on Plex 1.42.2.10156 | Service logs, exploit artifacts, honeypot replay | High |
| Root obtained twice by the same source, about 54 hours apart | Kernel log, service manager log, firewall log | High |
| Escalation code is embedded in the loader binary | Static analysis: exploit strings and a literal cleanup command that matches the kernel log | High |
| The working variant was xfrm/ESP, not RxRPC or Copy Fail | No module registration messages, no PAM trail, pre-existing mitigation | High, by elimination |
| Rootkit is eBPF-based, with a userland preload fallback | Six eBPF objects decrypted from the loader | High |
| No data-theft capability found | All encrypted content recovered and reviewed | Medium: one obfuscation layer not lifted |
| Artifact names are derived from the host machine-id | Formula reproduced exactly on the affected host | High |

Three unrelated actors were exploiting the same Plex flaw on the host during the same days. Only one of them escalated.

This was a campaign, not a targeted intrusion. The same loader and the same third-party bot were submitted to MalwareBazaar by another reporter on 22 October 2026, 22 seconds apart, and the operator's mining domain was listed on ThreatFox on 28 October. At least one other host was reached by the same two operations.

## Scope and method

The analysis is read-only and static: no malware sample was executed at any point. Evidence came from the incident archive kept by the responders plus the retained system logs of the affected host.

- **Logs:** five days of syslog, the tampered daemon log, and several months of kernel, authentication and package-manager logs.
- **Samples:** the on-disk loader, a memory capture of the running loader (identical hash), a memory capture of the miner, and files left by other actors.
- **Scanner output:** chkrootkit, rkhunter, debsums, dpkg verification and ClamAV runs taken during the response.
- **Honeypot material:** packet captures and codec files from a deliberately vulnerable replica the responders ran for one week after the incident.
- **Reverse engineering:** radare2, objdump and readelf on a copy of the loader; decryption of embedded content with OpenSSL once key and nonce were located.

The independent analysis was completed before reading the responders' own final report, then compared against it. Both reached the same escalation vector by different routes.

Victim-side addresses, hostnames, account names and service details are omitted. All times are UTC. Attacker infrastructure is listed in full because it is useful to defenders.

## Environment

The host ran a kernel built two weeks before Copy Fail was disclosed and never booted the newer kernel that was already installed. That gap, not a missing package update, is what left it exposed.

| Component | State at the time | Relevance |
| --- | --- | --- |
| Distribution | Ubuntu 24.04 LTS | Baseline |
| Running kernel | 6.17.0-23 (HWE), changelog signed 14 Apr 2026, booted 1 Oct 2026 | No fix for CVE-2026-31431, CVE-2026-43284 or CVE-2026-43500 in its changelog |
| Installed but not booted | 6.17.0-29 | A reboot had not been done |
| Plex Media Server | 1.42.2.10156, native package, running as an unprivileged service account | Vulnerable to Plex2Shell |
| `algif_aead` | Blocked since 4 May 2026 by the distribution's `kmod` mitigation file | Copy Fail path closed |
| `esp4`, `esp6`, `authencesn`, `rxrpc` | Present as loadable modules | Dirty Frag paths available |
| Unprivileged user namespaces | AppArmor restriction switched off at runtime by the LXD snap daemon, started 14 Oct | Lets an unprivileged process obtain network-admin capability inside a namespace |
| Kernel live patching | Client installed but failing its checks | No effective coverage |
| Unprivileged eBPF | Disabled | Irrelevant once root is obtained |

The distribution default restricts unprivileged user namespaces. The LXD snap writes a runtime sysctl drop-in that sets the restriction to 0, and it overrides both the default and any administrator file in `/etc/sysctl.d`. Whether this was strictly required for the exploit to succeed was not established.

## Timeline

Root was first obtained on 18 Oct at 01:25 UTC, 54 hours earlier than the responders had originally dated it, and containment came on 20 Oct at 15:33 UTC. Root processes are confirmed for two intervals inside that 62-hour span: about 2.5 hours after the first escalation and about 8 hours after the second.

| When (UTC, 2026) | Event | Source |
| --- | --- | --- |
| 14 Apr | Running kernel build signed | Package changelog |
| 4 May | `algif_aead` mitigation file installed | File birth time |
| 1 Oct | Last boot before the incident, into the unpatched kernel | Kernel log |
| 14 Oct 22:06 | LXD daemon started; user-namespace restriction set to 0 | Kernel and audit log |
| 17 Oct 06:17 | Earliest retained evidence of code execution as the Plex account: `wget` to a dropper host | Syslog |
| 17 Oct 22:00 | A first miner, run by a different actor, already working as the Plex account | Syslog |
| 18 Oct 01:24:55 | Connection to the Plex port from 91.92.40.202 | Firewall log |
| 18 Oct 01:25:22 | Kernel logs `drop_caches: 3` from a shell: **first root** | Kernel log |
| 18 Oct 01:25:23 | Service manager reload requested from inside the Plex service group | Syslog |
| 18 Oct 04:03 | Scheduled Plex restart; service manager sends SIGKILL to loader and miner and logs them as left-over processes | Syslog |
| 18 Oct 18:25 | A third actor's DDoS bot launcher written, as the Plex account | File time |
| 19 Oct 04:01 | Next scheduled restart finds no left-over processes: the first implant most likely died at the previous restart | Syslog |
| 20 Oct 07:41:34 | Connection to the Plex port from 91.92.40.202 again | Firewall log |
| 20 Oct 07:41:59 | `drop_caches: 3` again; loader and pid file rewritten: **second root** | Kernel log, file times |
| 20 Oct 07:42:01 | Service manager reload from inside the Plex service group | Syslog |
| 20 Oct 07:42:18 | Daemon log replaced with a copy missing three lines | File birth time, diff against syslog |
| 20 Oct 15:31 | Responders stop Plex; hidden processes die with the service group | Syslog |
| 20 Oct 15:40 | Persistence unit disabled; loader and unit quarantined | Shell audit log |
| 22 Oct | Plex upgraded to a fixed release | Package log |
| 26 Oct 23:50 | Reboot into a patched kernel; any loaded eBPF programs gone | Boot record |

Syslog retention starts on 16 Oct 22:00 UTC, so exploitation as the Plex account may have begun earlier than shown. Kernel logs go back to May and contain no earlier `drop_caches` entry, so root was not obtained this way before 18 Oct.

## Initial access

Every actor entered through Plex2Shell, a public unauthenticated chain against Plex Media Server that ends in the transcoder loading an attacker-supplied shared object as a codec. The public proof of concept lists four CVEs.

| CVE | Primitive |
| --- | --- |
| CVE-2026-96652 | Unauthenticated SSRF through the player timeline endpoint |
| CVE-2026-96654 | Loopback pivot past a dead authentication guard |
| CVE-2026-96655 | Transcoder SSRF and arbitrary-path file write |
| CVE-2026-96656 | Code execution through unsigned codec loading |

The malicious object runs a constructor that forks and executes a shell command, as the Plex service account. The responders' report also associates CVE-2025-69414 (token theft) with the chain; this analysis did not verify that link. Sources disagree on the first fixed build, so check the vendor advisory rather than relying on a number quoted here.

At least three separate operations used the flaw on this host within four days. They did not cooperate: one of them ships code to kill the others.

| Operation | What it ran | Privilege reached |
| --- | --- | --- |
| Rust loader with XMRig, delivered from 91.92.40.202 | LPE, eBPF rootkit, persistence, miner | root |
| Dropper scripts from 217.60.194.116 and 77.90.185.205, a proxy binary and a miner pointed at `ota.proxystream.st:3333` | Shell droppers, repeated every few seconds | Plex account only; writes failed with permission errors |
| "Spider" DDoS bot, launcher tagged `SPIDER_NAME='Jane'` | Bot binary under `/var/tmp`, private copies of `curl` and `wget` | Plex account only |

The exploit needs outbound access from the server to the vendor's cloud to validate a token. A host that cannot reach it is not exploitable by the public chain, which the honeypot confirmed by accident on its first day.

## Privilege escalation

The loader carries its own local privilege escalation and reached root about 25 seconds after the inbound exploit connection, both times. The evidence ties the binary to the kernel log directly.

**What links the binary to the event.** The loader contains this literal shell command:

```
( printf '3' > /proc/sys/vm/drop_caches ) 2>/dev/null || true
```

The kernel logged `sh (<pid>): drop_caches: 3` exactly twice in six months of history, at the two escalation times. Writing that file requires root. Dropping the page cache is the cleanup step of page-cache poisoning exploits: the file on disk is never modified, and evicting the cache removes the tampered copy.

**What the loader embeds.** Next to that command sit the working parts of three public exploits:

- Copy Fail (CVE-2026-31431): `AF_ALG` type `aead` with `authencesn(hmac(sha256),cbc(aes))`.
- Dirty Frag, xfrm/ESP variant (CVE-2026-43284): user and network namespace setup, `uid_map` and `setgroups` writes, loopback security associations, target `/usr/bin/su`.
- Dirty Frag, RxRPC variant (CVE-2026-43500): `rxrpc` keys named `evil%d`, target `/etc/passwd` with a `root::0:0` entry.

It also embeds a 184-byte ELF that is written over the cached image of `su`. Disassembled, it is `setgid(0)`, `setuid(0)`, `setgroups(0, 0)`, then `execve("/bin/sh")` with `TERM=xterm`.

**Which variant ran.** Elimination leaves one candidate.

| Candidate | Verdict | Reason |
| --- | --- | --- |
| Copy Fail | Ruled out | `algif_aead` blocked since May; the kernel never logged registration of the `PF_ALG` family during that boot |
| Dirty Frag, RxRPC | Ruled out | The kernel never logged registration of `PF_RXRPC` or the `rxrpc` key type during that boot; this host does log such registrations |
| Dirty Frag, xfrm/ESP | Consistent | Leaves no kernel message, bypasses PAM, needs user namespaces, which were unrestricted |
| Stolen root SSH key | Ruled out | The only root login near the first event is a five-minute monitoring job; both reloads came from the Plex service group, not a login session |
| sudo, setuid binaries, container escape | Ruled out | Checked by the responders; no `su` or `sudo` PAM entries in either window |

The authentication log has no `su` session at either time. That fits the ESP variant, which replaces the code of `su` in memory, and not the RxRPC variant, which goes through a real `su` with an emptied root password.

The responders independently reproduced Dirty Frag on a replica with the same kernel build and obtained uid 0, with `su` rewritten by a small root-shell ELF. That reproduction and this evidence agree.

## The toolkit

The loader is a single 6.4 MB statically linked, stripped Rust executable that contains everything it needs: the escalation, the rootkit, the persistence logic and the miner. All of its encrypted content was recovered.

**Build.** Rust, with a C component compiled by Debian GCC 12.2.0. Notable crates: `libbpf-rs`, `aes-gcm`, `zstd-safe`, `ureq` with `rustls`, `regex`, `nix`, and `aegis_vm`, a code-virtualisation and white-box obfuscation library. Command line: `attach [-d|--no-root|--only-root|--fetch-only|--single|--code]` or `detach`.

**Encryption.** Embedded payloads use AES-256-GCM. The 32-byte key is stored unprotected in the read-only data, and one fixed 12-byte nonce is reused for all six eBPF objects, so they share a keystream and an identical encrypted ELF header. Protected strings use the same key with a per-string nonce stored right after the ciphertext. The white-box library does not guard this key.

| Location (virtual address) | Content |
| --- | --- |
| `0x60f000`, 32 bytes | AES-256 key |
| `0x611048`, 12 bytes | Nonce for the eBPF objects |
| `0x491fd0` | Routine that decrypts an eBPF object |
| `0x492069` | Routine that decrypts a protected string |
| `0x5ef5d0` to `0x60c5b0` | Six encrypted eBPF objects, 7 to 39 KB each |
| `0x611118`, 3.25 MB | Encrypted, zstd-compressed XMRig |
| File offset `0x52b03f`, 16.5 KB | Plain `LD_PRELOAD` shared object |
| File offset `0x5316e0`, 184 bytes | Plain root-shell ELF written over `su` |

Decryption is plain AES-256-CTR with the counter block set to nonce followed by `00000002`, which is GCM without the tag check. The decompressed miner has the same SHA-256 as the miner captured from memory during the response, and no high-entropy region of the file is left unexplained.

**Protected strings.** There are four: the miner command line (base64, listing nine pools), a Monero address pattern, the operator's wallet, and the compressed miner.

**Miner hijacking.** The loader watches other processes and rewrites any Monero address it finds, in command-line arguments at `execve` time and in files as they are read, replacing it with the operator's wallet. Competing miners on the same host end up mining for this operator.

## eBPF rootkit

Concealment and self-protection run in the kernel as six eBPF programs loaded by the loader after it has root. The objects keep function names, map names and source-line records, so their behaviour can be read almost as source.

| Program | Hooks | Effect |
| --- | --- | --- |
| `hide_files` | `getdents64` entry and exit | Removes chosen file names from directory listings |
| `hide_pid` | `open`, `openat`, `dup*`, `fcntl`, `close*`, `getdents64` | Removes chosen process IDs from `/proc` listings |
| `anti_ptrace` | `ptrace`, `process_vm_readv`, `process_vm_writev` | Returns a permission error for attempts to attach to or read protected processes |
| `protect_signal` | `kill`, `tkill`, `tgkill` | Sends SIGKILL to any process that signals a protected process |
| `ghost` | `openat`, `read`, `newfstat`, `newfstatat`, `dup*`, `fcntl`, `close*` | Overwrites the read buffer with newlines and zeroes the reported size for chosen files |
| `cleaner` | `sched_process_exec`, raw `sys_enter` | Reports every `sh`, `bash`, `curl`, `wget`, `python`, `perl` execution to user space and kills processes the loader marks |

Each protection consults an exempt process name, so the operator's own tooling still sees and controls everything.

Three consequences matter for responders:

1. **Userland scanners are blind.** Tools that list `/proc` or directories cannot see what `hide_pid` and `hide_files` remove. The scans run during this response reported nothing related to the loader.
2. **Do not kill from a shell.** `protect_signal` kills the sender, so an interactive `kill` costs you your session. The init process is immune to SIGKILL, so stopping the enclosing service through the service manager does work, and that is how these processes were finally removed.
3. **A reboot removes the kernel part.** eBPF programs do not survive a reboot unless something reloads them, so confirming that persistence is gone and then rebooting is the real cleanup.

A userland fallback exists for runs without root: a small `LD_PRELOAD` library that wraps `getdents64`, `stat`, `lstat`, `fstatat`, `__xstat` and `__lxstat` to hide names and processes.

## Persistence, naming and log tampering

The loader installs a systemd unit and derives every artifact name from the host's machine-id, so names differ on each victim but are stable and predictable on any one host.

**Persistence observed.** One unit file in `/etc/systemd/system`, described as "System Management Daemon", of type `forking`, with `ExecStart=<loader path> attach`, `Restart=on-failure` and `RestartSec=30`. The loader ran `daemon-reload` and `enable` but did not start the unit: its processes stayed in the Plex service group. The unit would only have taken effect at the next boot.

That detail explains the second intrusion. The scheduled Plex restart under three hours after the first escalation killed the implant, no reboot followed, and the operator's automation simply exploited the host again two days later.

**Persistence the loader can also install.** None of these were found on the host, but the code is there:

- A file in `/etc/cron.d` with an `@reboot root <loader path> attach` entry.
- `LD_PRELOAD` exports appended to shell startup files, marked with the comment `# gpu-runtime-overlay`.
- Entries in `/etc/rc.local` and `/etc/profile.d`.
- A preload library with a `.so.1` name under a `.local` directory.

**Naming.** Each name is the first 16 hex characters of a SHA-256 over the machine-id (as text, without the trailing newline) immediately followed by a label.

| Artifact | Label | Location |
| --- | --- | --- |
| Loader binary | `loader-bin-v1` | `/usr/lib/.<16 hex>` |
| PID file | `loader-pid-v1` | `/run/.<16 hex>` |
| Unit name | `loader-svc-v1` | `/etc/systemd/system/<8 chars>.service`, encoding not reproduced |
| Process name | `loader-comm-v1` | 15 lowercase alphanumeric characters, encoding not reproduced |
| Miner process name | `loader-exec-v1` | Short numeric name, encoding not reproduced |

The first two were reproduced exactly from the affected host's machine-id. Because the names repeat, the second installation overwrote the first and the file times pointed only at the later date.

**Log tampering.** Nineteen seconds after the second escalation the daemon log was replaced by a root-owned copy with three lines removed: the service manager entries that named the loader process from two days earlier. The general syslog was not cleaned and still held those lines, which is how the edit was found. The loader lists `auth.log`, `syslog`, `messages`, `kern.log`, `daemon.log`, `secure`, `audit.log`, `utmp`, `wtmp` and shell history files as targets.

A side effect exposed the edit weeks later: the replacement file was owned by root, so after the next rotation the logging daemon could no longer write to it.

## Data theft assessment

Nothing in the recovered toolkit collects or exfiltrates credentials or files; it is built to mine and to hold the host against rival miners. That conclusion carries one stated gap.

What supports it:

- No path to keys, tokens, password stores, cloud credentials or environment files appears in the plain strings, the four protected strings or the six eBPF objects.
- The file-scanning module with its match pattern and replacement value is the wallet substitution described above, not a collector.
- Every encrypted region of the binary is accounted for.
- The responders found no attacker commands in the root shell audit log and no logins to hosted mail accounts from attacker addresses.

What limits it:

- The binary links a code-virtualisation library, and functions protected by it were not lifted.
- The loader has an HTTP client and a `--fetch-only` mode whose arguments on this host are unknown, so it could have pulled further content.
- `cleaner` receives the full command line of every shell and downloader execution. Secrets passed as arguments were visible to the loader, although no code was found that sends them anywhere.
- A root process can read anything. Absence of a collector in this binary does not prove nothing was read.

The practical reading: treat secrets on the host as exposed to an automated miner operator, with no sign of targeted theft.

## Detection and hunting

The cheapest reliable check is the host-specific file name, because it cannot be hidden from a calculation done elsewhere and needs no scanner.

**Per-host name check.** Compute the two expected paths and look for them from a trusted environment, ideally with the disk mounted offline or after a reboot:

```
id=$(tr -d '\n' < /etc/machine-id)
for label in loader-bin-v1 loader-pid-v1; do
  printf '%s%s' "$id" "$label" | sha256sum | cut -c1-16
done
# first value  -> /usr/lib/.<value>
# second value -> /run/.<value>
```

The rootkit filters directory listings but not lookups by exact path, so testing for these two paths works even on a live infected host. A clean result is still stronger when taken offline or after a reboot. The companion script `tools/check_host.sh` runs this test together with the persistence checks below, and accepts a mounted disk image.

**Log indicators that survive the rootkit.**

| Indicator | Where | Meaning |
| --- | --- | --- |
| `drop_caches: 3` from `sh` with no administrator action | Kernel log | Cleanup after page-cache poisoning |
| `Reloading requested from client PID … ('systemctl') (unit <an Internet-facing service>)` | Syslog | A service that should never manage units is doing so |
| Service stop reporting processes with random names that remain or are left over | Syslog | Foreign processes inside a service group |
| `wget` or `curl` progress output attributed to a media server process | Syslog | Dropper running under that service |
| A log file whose birth time is recent and whose owner changed to root | File metadata | In-place log replacement |
| Gaps between two logs that should agree | Syslog against daemon log | Selective line removal |
| Unit described as "System Management Daemon" with `attach` in `ExecStart` | Unit files | Loader persistence |
| `# gpu-runtime-overlay` in shell startup files | Home directories | Preload persistence |

**Live checks.** List loaded eBPF programs and compare against what your own tooling installs. Programs attached to `getdents64`, `kill`, `tkill`, `tgkill`, `ptrace` and `sched_process_exec` with no known owner deserve attention. Compare process IDs visible in `/proc` listings with those reachable by direct path.

**Network.** Outbound connections to the pools and addresses in the indicator list, and any stratum traffic from a media server.

Sending forwarded logs to another machine would have defeated the tampering here, because only local files were edited.

## Lessons and recommendations

Two ordinary gaps, an unpatched media server and a kernel update that was installed but never booted, were enough for a fully automated root compromise in under half a minute.

1. **A kernel update counts only after the reboot.** The fixed kernel was on disk for the whole incident. Track running version against installed version, and alert on the difference.
2. **Media servers do not belong on a host that matters.** Put them in a virtual machine or on a separate machine. A container shares the host kernel and would not have stopped this escalation.
3. **Check what your container tooling changes.** The LXD snap disables the AppArmor restriction on unprivileged user namespaces at runtime and overrides administrator settings. Verify the live value, not the configuration file.
4. **Module blocking works.** The distribution's `algif_aead` block closed one of the three embedded exploits. Blocking `rxrpc`, `esp4` and `esp6` where they are unused would have closed the others.
5. **Ship logs off the host.** Local log editing was the only anti-forensic step that touched history, and it was caught only because a second local log disagreed.
6. **Do not trust userland scanners after a root compromise.** With an eBPF rootkit loaded they report a clean system. Analyse from outside or after a reboot.
7. **Look at what you quarantined.** The escalation was considered unproven for a month while the binary that contained it sat in the evidence folder. Running `strings` on it would have answered the question on day one.
8. **Date the incident from logs, not file times.** Deterministic artifact names meant the second installation erased the timestamps of the first.
9. **Restrict outbound traffic from services.** The public exploit chain needs the server to reach the vendor cloud, and every dropper needed to download its payload.

A honeypot replica was useful for confirming the escalation and capturing second stages, but it was not needed to identify the vector. The evidence already on the host was sufficient.

## Indicators of compromise

Indicators marked *reported* come from the responders' notes and honeypot and were not re-verified in this analysis. Host-derived names are omitted because they differ on every victim; use the formula above.

**Files**

| SHA-256 | Description |
| --- | --- |
| `a8513f37db3089424693c687a3c64c03f36faa47d861abd0162c9bcb942c6a1f` | Rust loader, 6,464,360 bytes |
| `3774efe15677759c0f665df94455f8ecaf58bda6f288cb6394d100e5893c3f79` | XMRig embedded in the loader, 9,889,464 bytes, static PIE |
| `31eb9db333129f588baf5c1d5e7e7da119db0d1ff502da95408ef8d5a7e19f97` | Bot dropped as `/var/tmp/kworker` by another actor, 387,976 bytes |
| `c97d0ee1a7a8ca7c82dab3e584b5c423cf2098279dab551ab2be90fece282294` | "Spider" DDoS bot, 32-bit build (*reported*) |

**Network: root-level operation**

| Indicator | Role |
| --- | --- |
| `91.92.40.202` | Exploit source at both escalations; also seen as `:40175` outbound (*reported*) |
| `94.26.35.142:53535` | Outbound from the miner (*reported*) |
| `hello.itsmybirthdaytoday.pw:53535` | Mining endpoint in loader configuration |
| `213.218.160.252:53535` | Mining endpoint in loader configuration |
| `196.251.121.188:53535` | Mining endpoint in loader configuration |
| `pool.hashvault.sh:443`, `pool.hashvault.pro:443`, `mine.c3pool.com:13333`, `xmr.kryptex.network:7029`, `xmr-eu.kryptex.network:7029`, `gulf.moneroocean.stream:10004` | Public pools in loader configuration |

**Network: other operations on the same host**

| Indicator | Role |
| --- | --- |
| `217.60.194.116` | Dropper host; paths `/plex`, `/x`, `/docker` over HTTP |
| `77.90.185.205` | Dropper host; paths `/m/sh`, `/m/wee`; drops `myawesomeproxy` |
| `ota.proxystream.st:3333` | Stratum endpoint of a second miner |
| `94.154.43.7` | Automated exploit source against the honeypot (*reported*) |
| `94.154.43.68:48180`, `hand.genddos.st` | "Spider" bot control (*reported*) |
| `45.194.92.222` | Exploit source (*reported*) |

**Wallet**

```
83kPPGNWwFv7BRCPQN9UuuSnKL2W5UWviJeRTKFcvdunA9EAdjhCxcr6iTtTdcphuo55JjN2a5p5cjee9PZzTzrzArw1xCU
```

**Strings for rules**

```
loader-bin-v1  loader-svc-v1  loader-pid-v1  loader-comm-v1  loader-exec-v1  loader-config-hash-v1
BPF object decryption failed
invalid BPF decryption key
HIDECOMM_SENTINEL  HIDENAMES_SENTINEL
# gpu-runtime-overlay
POC_UNSHARE  POC_NO_UNSHARE  POC_TARGET_FILE  LPE_MAX_ITERS  LPE_SEED
Description=System Management Daemon
[cleaner] killed PID
[execve]    replaced arg in PID
[file-read] regex replaced in PID
```

**Loader key material**, for analysts with the same sample: AES-256 key `e83d2264ca6a267457cacab544a7c53bf1e0acd41ce9012e68013b90fe765284`, eBPF object nonce `a911a49cf0ea81abc43ff651`.

## Limitations and open questions

The escalation vector is established by elimination and corroboration, not by a captured exploit run. The points below are what a reader should weigh.

- **No direct trace of the ESP exploit exists.** It leaves none. The conclusion rests on the embedded code, the cleanup command in the kernel log, the absence of traces the other variants would leave, and the responders' reproduction.
- **Exploit attribution inside the binary is by resemblance.** Strings and constants match the public descriptions of Copy Fail and Dirty Frag. The escalation code was not disassembled function by function.
- **The user-namespace setting is inferred for the incident dates.** The daemon that disables the restriction started four days earlier in the same boot, and the live value was confirmed only afterwards.
- **The loader was not fully reversed.** Functions protected by the virtualisation library, the HTTP client paths and the encodings of three derived names remain unexamined.
- **The dropper is missing.** The shared object that Plex loaded to start the loader was deleted by the attacker and not recovered, so the exact launch arguments are unknown.
- **The first implant's fate is inferred.** Its death at the scheduled restart fits the logs but was not observed directly.
- **Earliest access is bounded by retention.** Syslog begins the evening of 16 Oct.
- **Identifiers are as found in the evidence.** CVE numbers and fixed versions for the Plex chain are quoted from the public proof of concept and were not checked against vendor advisories.
- **Honeypot findings are second-hand.** The replica and its captures were destroyed after the responders' report, so those results could not be re-examined.
