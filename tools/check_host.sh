#!/bin/sh
# check_host.sh - look for traces of the Rust loader described in REPORT.md.
#
# Read-only. Run as root. Set ROOT=/mnt/image to check a mounted disk offline.
# Exit status: 0 = nothing found, 1 = at least one hit, 2 = could not run.
#
# The loader derives its file names from /etc/machine-id, so the expected
# paths are computed per host. The eBPF rootkit filters directory listings
# (getdents64) but not lookups by exact path, so the tests below still work
# on a live infected host. A clean result on a live host is still weaker than
# the same check done offline or after a reboot.

set -u
R="${ROOT:-}"
hits=0
note() { printf '%s\n' "$*"; }
hit()  { hits=$((hits + 1)); printf 'HIT: %s\n' "$*"; }

if [ ! -r "$R/etc/machine-id" ]; then
    note "cannot read $R/etc/machine-id"
    exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    note "sha256sum not available"
    exit 2
fi

id=$(tr -d '\n' < "$R/etc/machine-id")
derive() { printf '%s%s' "$id" "$1" | sha256sum | cut -c1-16; }

bin="/usr/lib/.$(derive loader-bin-v1)"
pid="/run/.$(derive loader-pid-v1)"

# 1. Host-specific loader and pid file.
for p in "$bin" "$pid"; do
    if [ -e "$R$p" ] || [ -L "$R$p" ]; then hit "derived path exists: $p"; fi
done

# 2. Persistence unit: fixed description, ExecStart ending in "attach".
for d in "$R/etc/systemd/system" "$R/usr/lib/systemd/system" "$R/run/systemd/system"; do
    [ -d "$d" ] || continue
    for f in "$d"/*.service; do
        [ -f "$f" ] || continue
        if grep -qE '^Description=System Management Daemon$' "$f" 2>/dev/null &&
           grep -qE '^ExecStart=.* attach$' "$f" 2>/dev/null; then
            hit "persistence unit: $f"
        fi
    done
done

# 3. Cron persistence.
for f in "$R"/etc/cron.d/*; do
    [ -f "$f" ] || continue
    if grep -qE '^@reboot[[:space:]]+root[[:space:]]+/usr/lib/\.[0-9a-f]{16}[[:space:]]+attach' "$f" 2>/dev/null; then
        hit "cron persistence: $f"
    fi
done

# 4. LD_PRELOAD persistence marker in shell startup files.
for f in "$R"/etc/profile "$R"/etc/bash.bashrc "$R"/etc/profile.d/* "$R"/etc/rc.local \
         "$R"/root/.bashrc "$R"/root/.bash_profile "$R"/root/.profile \
         "$R"/root/.bash_login "$R"/root/.zshrc "$R"/root/.zprofile \
         "$R"/home/*/.bashrc "$R"/home/*/.bash_profile "$R"/home/*/.profile \
         "$R"/home/*/.bash_login "$R"/home/*/.zshrc "$R"/home/*/.zprofile; do
    [ -f "$f" ] || continue
    if grep -q '# gpu-runtime-overlay' "$f" 2>/dev/null; then hit "preload marker in $f"; fi
done

# 5. Kernel log: page cache dropped from a shell. Legitimate on hosts where an
#    administrator or a tuning job does this, so treat as a lead, not proof.
dc=0
for f in "$R/var/log/kern.log" "$R/var/log/kern.log.1"; do
    [ -r "$f" ] || continue
    n=$(grep -ac 'sh ([0-9]*): drop_caches: 3' "$f" 2>/dev/null)
    dc=$((dc + ${n:-0}))
done
if [ "$dc" -gt 0 ]; then note "LEAD: $dc 'sh: drop_caches: 3' line(s) in recent kernel logs"; fi

note "expected loader path: $bin"
note "expected pid path:    $pid"
if [ "$hits" -gt 0 ]; then
    note "RESULT: $hits hit(s)"
    exit 1
fi
note "RESULT: clean"
exit 0
