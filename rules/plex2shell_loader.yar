/*
   Rules for the toolkit described in REPORT.md.
   Strings were taken from one analysed sample
   (sha256 a8513f37db3089424693c687a3c64c03f36faa47d861abd0162c9bcb942c6a1f).
   Other builds may differ; treat a miss as inconclusive.
*/

rule Plex2Shell_Rust_Loader
{
    meta:
        description = "Rust loader with embedded LPE, eBPF rootkit and XMRig"
        author = "Hugo L. Espuny"
        reference = "https://github.com/fakehec"
        date = "2026-11-21"
        hash = "a8513f37db3089424693c687a3c64c03f36faa47d861abd0162c9bcb942c6a1f"

    strings:
        $label_bin  = "loader-bin-v1" ascii
        $label_svc  = "loader-svc-v1" ascii
        $label_pid  = "loader-pid-v1" ascii
        $label_comm = "loader-comm-v1" ascii
        $bpf_fail   = "BPF object decryption failed" ascii
        $bpf_key    = "invalid BPF decryption key" ascii
        $sentinel   = "HIDECOMM_SENTINEL" ascii
        $overlay    = "# gpu-runtime-overlay" ascii
        $poc_env    = "POC_UNSHARE" ascii
        $lpe_env    = "LPE_MAX_ITERS" ascii
        $cleaner    = "[cleaner] killed PID" ascii
        $drop       = "( printf '3' > /proc/sys/vm/drop_caches )" ascii
        $aes_key    = { e8 3d 22 64 ca 6a 26 74 57 ca ca b5 44 a7 c5 3b
                        f1 e0 ac d4 1c e9 01 2e 68 01 3b 90 fe 76 52 84 }

    condition:
        uint32(0) == 0x464c457f and
        ( $aes_key or 5 of them )
}

rule Plex2Shell_Preload_Library
{
    meta:
        description = "LD_PRELOAD fallback rootkit embedded in the loader"
        author = "Hugo L. Espuny"
        date = "2026-11-21"

    strings:
        $s1 = "HIDENAMES_SENTINEL" ascii
        $s2 = "HIDECOMM_SENTINEL" ascii
        $s3 = "g_hide_names" ascii
        $s4 = "orig_getdents64" ascii

    condition:
        uint32(0) == 0x464c457f and filesize < 200KB and 3 of them
}

rule Plex2Shell_Su_Root_Shell_Payload
{
    meta:
        description = "184-byte ELF written over the cached image of su: setgid, setuid, setgroups, execve /bin/sh"
        author = "Hugo L. Espuny"
        date = "2026-11-21"

    strings:
        $code = { 31 ff 31 f6 31 c0 b0 6a 0f 05 b0 69 0f 05 b0 74 0f 05 }
        $term = "TERM=xterm" ascii
        $sh   = "/bin/sh" ascii

    condition:
        uint32(0) == 0x464c457f and filesize < 4KB and all of them
}

rule Plex2Shell_Loader_Persistence_Unit
{
    meta:
        description = "systemd unit installed by the loader"
        author = "Hugo L. Espuny"
        date = "2026-11-21"

    strings:
        $desc = "Description=System Management Daemon" ascii
        $exec = /ExecStart=\/usr\/lib\/\.[0-9a-f]{16} attach/ ascii
        $type = "Type=forking" ascii

    condition:
        filesize < 2KB and all of them
}

rule Plex2Shell_eBPF_Rootkit_Object
{
    meta:
        description = "Decrypted eBPF objects of the loader rootkit: hide_files, hide_pid, anti_ptrace, protect_signal, ghost, cleaner"
        author = "Hugo L. Espuny"
        date = "2026-11-21"
        note = "Matches the objects after decryption or when dumped from memory; inside the loader they are AES-GCM encrypted"

    strings:
        $src_hide_files = "/build/src/bpf/hide_files.bpf.c" ascii
        $src_hide_pid   = "/build/src/bpf/hide_pid.bpf.c" ascii
        $src_ptrace     = "/build/src/bpf/anti_ptrace.bpf.c" ascii
        $src_signal     = "/build/src/bpf/protect_signal.bpf.c" ascii
        $src_ghost      = "/build/src/bpf/ghost.bpf.c" ascii
        $src_cleaner    = "/build/src/bpf/cleaner.bpf.c" ascii

        $hf1 = "hf_process_entry" ascii
        $hf2 = "hidden_filenames" ascii
        $hp1 = "pending_proc_opens" ascii
        $hp2 = "hidden_names" ascii
        $ap1 = "ap_vm_readv" ascii
        $ap2 = "ap_vm_writev" ascii
        $ps1 = "protect_tkill" ascii
        $ps2 = "protect_tgkill" ascii
        $gh1 = "pending_ghost_dups" ascii
        $gh2 = "ghost_fds" ascii
        $cl1 = "enforce_kills" ascii
        $cl2 = "to_kill" ascii

    condition:
        uint32(0) == 0x464c457f and uint16(18) == 0xf7 and filesize < 1MB and
        (
            any of ($src_*) or
            ($hf1 and $hf2) or ($hp1 and $hp2) or ($ap1 and $ap2) or
            ($ps1 and $ps2) or ($gh1 and $gh2) or ($cl1 and $cl2)
        )
}
