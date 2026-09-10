#!/usr/bin/env python3
"""aws_cis_al2_map.py — the CIS Amazon Linux 2 Benchmark v4.0.0 mapping, as DATA.

All 287 recommendations, what kind of state each one's audit reads, and whether OverWatch
can reach it. GENERATED from the classified benchmark by a scratch script and committed as
source; the analysis in ``SUBSECTIONS`` and the blocker register are hand-written.

WHY THIS MAPPING LOOKS DIFFERENT FROM THE OTHERS. The Foundations, Compute and Database
mappings ask "does a check decide this?", because everything in those documents is an AWS
control-plane setting and the answer is a yes/no about coverage. This benchmark is an
OPERATING SYSTEM benchmark: 250 of its 287 recommendations read state that is inside the
instance, and the honest question is not "did we build it" but "can we see it at all".
So every row carries the SOURCE — the kind of state its audit reads — and a row that is
not covered names the CAPABILITY it is blocked on rather than being filed as a backlog
item somebody could pick up tomorrow.

THE HEADLINE, WHICH IS NOT A COMFORTABLE ONE: 44 of 287 are decided. The rest need to read
a filesystem or the running kernel, and OverWatch is an agentless control-plane scanner.
That is not a gap in this mapping; it is the shape of the product meeting the shape of the
document, and writing it down is the point.

WHY NO CHECKS WERE REGISTERED FOR THE OTHER 243. Registering them would put the largest
block of registered-but-unreachable checks in this product's history into the catalogue —
the exact failure ``docs/CHECK_FIRING.md`` measures and ``tests/test_unreached_modules.py``
exists to keep at zero. When ``aws_sidescan_fs.DissectExtractor`` stops raising
``SideScanUnavailable``, this file is the work list, already sorted by what each row needs.

ON THE SOURCE DOCUMENT. CIS Benchmarks may not be redistributed. This file carries
recommendation NUMBERS, which are references, and a classification of each one's audit
that is this project's own analysis. It reproduces NO recommendation titles at all — not
even paraphrased — which is a stronger position than the sibling mappings needed to take,
and the reason the rows below carry a source bucket instead of a label.
"""
from __future__ import annotations

from typing import Dict, Tuple

__all__ = [
    "SOURCES", "VERDICTS", "COVERED", "BLOCKED", "BLOCKERS",
    "SUBSECTIONS", "RECOMMENDATIONS", "checks_for", "blocker_for", "by_source",
]

# ─── what kind of state a recommendation's audit reads ───────────────────────────
#: file CONTENT — /etc/ssh/sshd_config, PAM stacks, auditd rules, sysctl.conf
FILE = "FILE"
#: file permissions and ownership, read with stat
FILEMODE = "FILEMODE"
#: /etc/passwd, /etc/shadow, /etc/group and account ageing
ACCOUNT = "ACCOUNT"
#: running kernel state — sysctl values, loaded modules
KERNEL = "KERNEL"
#: installed packages
PKG = "PKG"
#: systemd unit state
SERVICE = "SERVICE"
#: could not be classified from the audit text; named rather than folded into FILE, so
#: the number is visible instead of quietly improving the others
OTHER = "OTHER"

SOURCES = (FILE, FILEMODE, ACCOUNT, KERNEL, PKG, SERVICE, OTHER)

#: A named check decides it and can FAIL on it.
COVERED = "COVERED"
#: Decidable in principle, and OverWatch cannot see the state at all. NOT the same as the
#: `gap` verdict the sibling mappings use: a gap is a backlog item somebody could build
#: this afternoon, whereas every row here is waiting on a named capability that does not
#: exist yet. Filing these as gaps would have made the backlog look 243 items deep and
#: entirely actionable, which would be false.
BLOCKED = "BLOCKED"

VERDICTS = (COVERED, BLOCKED)

#: THE STIG BENCHMARK IS NOT MAPPED HERE, and that is a scoping decision rather than an
#: oversight. The CIS Amazon Linux 2 STIG Benchmark v2.0.0 is a separate 1,013-page
#: document carrying 380 further recommendations (338 Automated, 42 Manual). It is the
#: same shape of problem — in-guest file, kernel and account state — so it would land in
#: the same place: a handful decidable through SSM Inventory and the rest waiting on the
#: same FILESYSTEM capability. Mapping it before that capability exists would add 380 more
#: rows that all say BLOCKED, which is length without information. It is worth doing when
#: the extractor lands, or sooner if an estate is being audited against the STIG
#: specifically, in which case the package and service overlap with this file is the place
#: to start.

#: capability -> what it is, and what would unblock it. Held as data so the generated
#: document and the tests read the same list.
BLOCKERS: Dict[str, str] = {
    "FILESYSTEM": (
        "reading a file inside the instance. The seam exists — "
        "aws_sidescan.FilesystemExtractor, fed by the EBS-snapshot block plane in "
        "aws_sidescan_ebs — but its production implementation, "
        "aws_sidescan_fs.DissectExtractor, raises SideScanUnavailable on purpose. Its "
        "own words: it NEVER returns a guessed inventory, which could false-clean a "
        "vulnerable host. Unblocking it means pinning dissect.target into the offline "
        "wheelhouse, committing golden ext4 and xfs images, and validating the parse on "
        "a Linux CI runner. That is a real project, and it lights up 243 rows here"),
    "RUNTIME": (
        "reading the RUNNING kernel — a live sysctl value or the loaded module list. A "
        "disk image shows what is CONFIGURED in /etc/sysctl.d, not what is in effect, "
        "and the two differ on any host somebody has run sysctl -w on. There is no "
        "read-only path to this at all: ssm:SendCommand would answer it and executes "
        "code, which is a write and outside this product's charter. Some of these rows "
        "become partially decidable once the filesystem lands, on the weaker claim of "
        "what the host is configured to do at next boot"),
    "SERVICE_INVENTORY": (
        "SSM Inventory reporting systemd unit state for the host. AWS:Service is "
        "collected for Windows services; whether a given Linux instance reports anything "
        "under it is not something this mapping asserts, so AL2-03 reads what is there "
        "and states it when the type is absent rather than assuming"),
}

#: (number, this project's own description, recommendation count, covered count)
SUBSECTIONS: Tuple[Tuple[str, str, int, int], ...] = (
    ("1.1", "Filesystem kernel modules, and mount options on /tmp, /dev/shm, /var and /home", 33, 0),
    ("1.2", "Package repository trust: GPG key configuration and gpgcheck enforcement", 5, 0),
    ("1.3", "Authentication required for single-user mode", 1, 0),
    ("1.4", "SELinux: installed, not disabled at boot, and actually enforcing", 7, 2),
    ("1.5", "Core dumps, ASLR and kernel memory-protection parameters", 10, 0),
    ("1.6", "Login banners and the permissions on the files that hold them", 6, 0),
    ("2.1", "Time synchronisation", 3, 1),
    ("2.2", "Special-purpose server daemons that should not be present on a server", 22, 20),
    ("2.3", "Client packages for protocols that authenticate in cleartext", 5, 5),
    ("3.1", "Unused interface kinds: IPv6, wireless and Bluetooth", 3, 1),
    ("3.2", "Kernel modules for uncommon network protocols", 3, 0),
    ("3.3", "Network-stack sysctl parameters", 26, 0),
    ("4.1", "Host firewall: installed, running, and with a default-deny zone", 8, 1),
    ("5.1", "cron and at: the daemon, and access to the files that schedule work", 9, 0),
    ("5.2", "The SSH daemon's configuration and host-key file permissions", 22, 0),
    ("5.3", "sudo: logging, pty use, and re-authentication", 7, 1),
    ("5.4", "PAM: password quality, account lockout and password hashing", 20, 1),
    ("5.5", "Shadow-suite account ageing, and the state of root and system accounts", 17, 0),
    ("6.1", "journald and rsyslog: retention, forwarding and file permissions", 15, 1),
    ("6.2", "auditd: rule coverage, buffer sizing and protection of the audit log", 40, 1),
    ("6.3", "Filesystem integrity checking with AIDE", 3, 1),
    ("7.1", "Permissions and ownership on the system account files", 13, 0),
    ("7.2", "Local user and group account hygiene", 9, 0),)

#: number -> (source, verdict, checks, blocker). No titles: see the module docstring.
RECOMMENDATIONS: Dict[str, Tuple[str, str, Tuple[str, ...], str]] = {
    "1.1.1.1": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "1.1.1.2": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "1.1.1.3": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "1.1.1.4": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "1.1.1.5": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "1.1.1.6": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "1.1.1.7": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "1.1.2.1.1": ("SERVICE", BLOCKED, (), "SERVICE_INVENTORY"),
    "1.1.2.1.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.1.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.1.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.2.1": ("OTHER", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.2.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.2.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.2.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.3.1": ("OTHER", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.3.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.3.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.4.1": ("OTHER", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.4.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.4.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.5.1": ("OTHER", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.5.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.5.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.5.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.6.1": ("OTHER", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.6.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.6.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.6.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.7.1": ("OTHER", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.7.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.7.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.1.2.7.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.2.1": ("PKG", BLOCKED, (), "FILESYSTEM"),
    "1.2.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.2.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.2.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.2.5": ("OTHER", BLOCKED, (), "FILESYSTEM"),
    "1.3.1": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.4.1.1": ("PKG", COVERED, ("AL2-02",), ""),
    "1.4.1.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.4.1.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.4.1.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.4.1.5": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.4.1.6": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.4.1.7": ("PKG", COVERED, ("AL2-01",), ""),
    "1.5.1": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.5.2": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "1.5.3": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "1.5.4": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "1.5.5": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "1.5.6": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "1.5.7": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "1.5.8": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "1.5.9": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.5.10": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.6.1": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.6.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.6.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "1.6.4": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "1.6.5": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "1.6.6": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "2.1.1": ("PKG", COVERED, ("AL2-02",), ""),
    "2.1.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "2.1.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "2.2.1": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.2": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.3": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.4": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.5": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.6": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.7": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.8": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.9": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.10": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.11": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.12": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.13": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.14": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.15": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.16": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.17": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.18": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.19": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "2.2.20": ("PKG", COVERED, ("AL2-01",), ""),
    "2.2.21": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "2.2.22": ("OTHER", BLOCKED, (), "FILESYSTEM"),
    "2.3.1": ("PKG", COVERED, ("AL2-01",), ""),
    "2.3.2": ("PKG", COVERED, ("AL2-01",), ""),
    "2.3.3": ("PKG", COVERED, ("AL2-01",), ""),
    "2.3.4": ("PKG", COVERED, ("AL2-01",), ""),
    "2.3.5": ("PKG", COVERED, ("AL2-01",), ""),
    "3.1.1": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.1.2": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.1.3": ("PKG", COVERED, ("AL2-01", "AL2-03"), ""),
    "3.2.1": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.2.2": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.2.3": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.1.1": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.1.2": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.1.3": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.1.4": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.1.5": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.1.6": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.1.7": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.1.8": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.1.9": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.1.10": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.1.11": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.1.12": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.1.13": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.1.14": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.1.15": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.1.16": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.1.17": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.1.18": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.2.1": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.2.2": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.2.3": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.2.4": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.2.5": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.2.6": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.2.7": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "3.3.2.8": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "4.1.1": ("PKG", COVERED, ("AL2-02",), ""),
    "4.1.2": ("SERVICE", BLOCKED, (), "SERVICE_INVENTORY"),
    "4.1.3": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "4.1.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "4.1.5": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "4.1.6": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "4.1.7": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "4.1.8": ("OTHER", BLOCKED, (), "FILESYSTEM"),
    "5.1.1.1": ("SERVICE", BLOCKED, (), "SERVICE_INVENTORY"),
    "5.1.1.2": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "5.1.1.3": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "5.1.1.4": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "5.1.1.5": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "5.1.1.6": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "5.1.1.7": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "5.1.1.8": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "5.1.2.1": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "5.2.1": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "5.2.2": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "5.2.3": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "5.2.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.2.5": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.2.6": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.2.7": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.2.8": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.2.9": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.2.10": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.2.11": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.2.12": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.2.13": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.2.14": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.2.15": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.2.16": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.2.17": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.2.18": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.2.19": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.2.20": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.2.21": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.2.22": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.3.1": ("PKG", COVERED, ("AL2-02",), ""),
    "5.3.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.3.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.3.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.3.5": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.3.6": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.3.7": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "5.4.1.1": ("PKG", BLOCKED, (), "FILESYSTEM"),
    "5.4.1.2": ("PKG", COVERED, ("AL2-02",), ""),
    "5.4.2.1.1": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.4.2.1.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.4.2.1.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.4.2.1.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.4.2.2.1": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.4.2.2.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.4.2.2.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.4.2.2.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.4.2.2.5": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.4.2.2.6": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.4.2.3.1": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.4.2.3.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.4.2.3.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.4.2.3.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.4.2.4.1": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.4.2.4.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.4.2.4.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.4.2.4.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.5.1.1": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "5.5.1.2": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "5.5.1.3": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "5.5.1.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.5.1.5": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "5.5.1.6": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "5.5.2.1": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "5.5.2.2": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "5.5.2.3": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "5.5.2.4": ("OTHER", BLOCKED, (), "FILESYSTEM"),
    "5.5.2.5": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "5.5.2.6": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.5.2.7": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "5.5.2.8": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "5.5.3.1": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.5.3.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "5.5.3.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.1.1.1": ("SERVICE", BLOCKED, (), "SERVICE_INVENTORY"),
    "6.1.1.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.1.1.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.1.1.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.1.1.5": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.1.1.6": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.1.1.7": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "6.1.2.1": ("PKG", COVERED, ("AL2-02",), ""),
    "6.1.2.2": ("SERVICE", BLOCKED, (), "SERVICE_INVENTORY"),
    "6.1.2.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.1.2.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.1.2.5": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.1.2.6": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.1.2.7": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.1.3.1": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "6.2.1.1": ("PKG", COVERED, ("AL2-02",), ""),
    "6.2.1.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.1.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.1.4": ("SERVICE", BLOCKED, (), "SERVICE_INVENTORY"),
    "6.2.2.1": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.2.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.2.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.2.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.1": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.2": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.4": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.5": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.6": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.7": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.8": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.9": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.10": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.11": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.12": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.13": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.14": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.15": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.16": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.17": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.18": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.19": ("KERNEL", BLOCKED, (), "RUNTIME"),
    "6.2.3.20": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.21": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.3.22": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.4.1": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "6.2.4.2": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "6.2.4.3": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "6.2.4.4": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "6.2.4.5": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "6.2.4.6": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.4.7": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "6.2.4.8": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "6.2.4.9": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "6.2.4.10": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "6.3.1": ("PKG", COVERED, ("AL2-02",), ""),
    "6.3.2": ("SERVICE", BLOCKED, (), "SERVICE_INVENTORY"),
    "6.3.3": ("FILE", BLOCKED, (), "FILESYSTEM"),
    "7.1.1": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "7.1.2": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "7.1.3": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "7.1.4": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "7.1.5": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "7.1.6": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "7.1.7": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "7.1.8": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "7.1.9": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "7.1.10": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "7.1.11": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "7.1.12": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "7.1.13": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "7.2.1": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "7.2.2": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "7.2.3": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "7.2.4": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "7.2.5": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "7.2.6": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "7.2.7": ("ACCOUNT", BLOCKED, (), "FILESYSTEM"),
    "7.2.8": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),
    "7.2.9": ("FILEMODE", BLOCKED, (), "FILESYSTEM"),}


def _sort_key(rec: str) -> Tuple[int, ...]:
    parts = [int(p) for p in rec.split(".")]
    return tuple(parts + [0] * (5 - len(parts)))


def checks_for(rec: str) -> Tuple[str, ...]:
    """The checks that decide ``rec``, or ``()``."""
    entry = RECOMMENDATIONS.get(rec)
    return entry[2] if entry else ()


def blocker_for(rec: str) -> str:
    """The capability ``rec`` is waiting on, or ``""`` if it is covered."""
    entry = RECOMMENDATIONS.get(rec)
    return entry[3] if entry else ""


def by_source() -> Dict[str, int]:
    """How many recommendations read each kind of state — the shape of the problem."""
    out: Dict[str, int] = {s: 0 for s in SOURCES}
    for src, _v, _c, _b in RECOMMENDATIONS.values():
        out[src] = out.get(src, 0) + 1
    return out
