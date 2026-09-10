#!/usr/bin/env python3
"""aws_cis_al2.py — the CIS Amazon Linux 2 Benchmark v4.0.0 controls OverWatch can
actually reach, and an honest account of the ones it cannot.

WHY THIS MODULE IS SMALL AND THE BENCHMARK IS NOT. The benchmark carries 287
recommendations and they are IN-GUEST operating-system state: the content of
``/etc/ssh/sshd_config``, PAM stacks, sysctl values, mount options, file modes, auditd
rules. OverWatch reads the AWS control plane. Classifying all 287 by the kind of state
their own audit commands read gives:

    file content   125 (44%)      kernel runtime   46 (16%)
    file modes      41 (14%)      packages         37 (13%)
    accounts        21 ( 7%)      services          7 ( 2%)
    unclassified    10 ( 3%)

Everything except the packages and services needs to read a filesystem, and the seam that
would do that — ``aws_sidescan_fs.DissectExtractor`` — deliberately raises
``SideScanUnavailable`` until a golden ext4/xfs image is validated on a Linux CI runner.
That module's own words: it "NEVER returns a guessed inventory (which could false-clean a
vulnerable host)". Registering checks for those 250 recommendations would put the largest
block of registered-but-unreachable checks in this product's history into the catalogue —
the exact failure ``docs/CHECK_FIRING.md`` and the firing ratchets exist to prevent.

SO THIS MODULE COVERS THE PACKAGE AND SERVICE CONTROLS, THROUGH SSM INVENTORY, and
``aws_cis_al2_map.py`` records what every other recommendation would need. When the
filesystem extractor lands, the map is the work list.

ON ``AWS:Service`` — AN ASSUMPTION DELIBERATELY NOT MADE. SSM Inventory's ``AWS:Service``
type collects Windows services; whether a given Linux host reports anything under it is
not something this module asserts. It reads what the instance actually has and says so
when the type is absent, rather than hard-coding a claim about AWS's inventory schema that
would silently become wrong. The package type, ``AWS:Application``, is populated on Linux
and is what the 37 package recommendations are decided from.

ON THE SOURCE DOCUMENT. CIS Benchmarks may not be redistributed, so the PDF is not in this
repository and no title, rationale, audit, impact or remediation prose is copied from it.
What is cited is the recommendation NUMBER, which is a reference, together with the
PACKAGE OR UNIT NAME — a fact about the operating system rather than the benchmark's
prose. Every description here is this project's own.

Pure. No boto3, no network, no I/O. The scanner passes in what it already fetched.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from engine import aws_checkdef as _cd
from engine.aws_checkdef import CheckDef as _C, Perm as _P

__all__ = [
    "PROHIBITED_PACKAGES", "REQUIRED_PACKAGES", "PROHIBITED_UNITS",
    "prohibited_packages", "missing_required_packages", "prohibited_units",
    "assessability", "CHECKS",
]

#: package -> (recommendation, what it is and why the benchmark wants it gone).
#:
#: The package NAME is the fact the audit turns on and is carried verbatim; the reason is
#: this project's own. Grouped roughly by what an attacker gets from each.
PROHIBITED_PACKAGES: Dict[str, Tuple[str, str]] = {
    # ── cleartext protocols: credentials cross the network in the clear ──────────
    "telnet-server": ("2.2.15", "a telnet daemon, which authenticates in cleartext"),
    "telnet": ("2.3.4", "a telnet client, which sends credentials in cleartext"),
    "tftp-server": ("2.2.16", "a TFTP daemon, which has no authentication at all"),
    "tftp": ("2.3.5", "a TFTP client"),
    "ftp": ("2.3.1", "an FTP client, which authenticates in cleartext"),
    "vsftpd": ("2.2.7", "an FTP daemon"),
    "ypserv": ("2.2.10", "a NIS server, a protocol that distributes password hashes "
                         "over the network with no transport security"),
    "ypbind": ("2.3.3", "a NIS client"),
    "openldap-clients": ("2.3.2", "an LDAP client, which the benchmark treats as "
                                  "unnecessary attack surface on a server"),
    # ── network daemons: each is a listening service and a patching obligation ───
    "dhcp": ("2.2.3", "a DHCP server"),
    "bind": ("2.2.4", "a DNS server"),
    "dnsmasq": ("2.2.5", "a lightweight DNS/DHCP server"),
    "samba": ("2.2.6", "an SMB/CIFS file server"),
    "dovecot": ("2.2.8", "an IMAP/POP3 server"),
    "nfs-utils": ("2.2.9", "an NFS server"),
    "cups": ("2.2.11", "a print server"),
    "rpcbind": ("2.2.12", "the RPC port mapper, which enumerates RPC services to "
                          "anything that can reach it"),
    "rsync": ("2.2.13", "an rsync daemon"),
    "net-snmp": ("2.2.14", "an SNMP agent, historically deployed with a default "
                           "community string"),
    "squid": ("2.2.17", "a web proxy, which can be abused as an open relay"),
    "httpd": ("2.2.18", "a web server"),
    "xinetd": ("2.2.19", "a super-server that launches other network daemons"),
    "autofs": ("2.2.1", "an automounter, which mounts removable and remote media on "
                        "access"),
    "avahi": ("2.2.2", "an mDNS responder, which advertises the host on the local "
                       "network"),
    "bluez": ("3.1.3", "the Bluetooth stack, which is attack surface with no purpose "
                       "on a server"),
    "xorg-x11-server-common": ("2.2.20", "an X11 server"),
    "mcstrans": ("1.4.1.7", "the SELinux MCS translation daemon, which the benchmark "
                            "treats as unnecessary"),
}

#: package -> (recommendation, what breaks without it).
REQUIRED_PACKAGES: Dict[str, Tuple[str, str]] = {
    "audit": ("6.2.1.1", "auditd, without which the host produces no kernel audit "
                         "trail at all — the record every other detective control on "
                         "the host assumes exists"),
    "rsyslog": ("6.1.2.1", "rsyslog, without which logs are not forwarded off the "
                           "host and are lost with it"),
    "aide": ("6.3.1", "AIDE, the filesystem integrity baseline; without it a changed "
                      "system binary leaves no trace"),
    "sudo": ("5.3.1", "sudo, without which privilege elevation is shared root "
                      "passwords and is unattributable"),
    "chrony": ("2.1.1", "a time daemon; without synchronised time, log correlation "
                        "across hosts and against CloudTrail is unreliable"),
    "libselinux": ("1.4.1.1", "the SELinux userspace, without which SELinux cannot be "
                              "enforcing"),
    "firewalld": ("4.1.1", "a host firewall, without which the security group is the "
                           "only network control the instance has"),
    "libpwquality": ("5.4.1.2", "the password-quality library PAM uses to enforce "
                                "complexity"),
}

#: systemd unit -> (recommendation, what it runs). Read opportunistically — see the
#: module docstring on why no claim is made about which hosts report services at all.
PROHIBITED_UNITS: Dict[str, Tuple[str, str]] = {
    "autofs.service": ("2.2.1", "the automounter"),
    "avahi-daemon.socket": ("2.2.2", "the mDNS responder"),
    "dhcpd.service": ("2.2.3", "a DHCP server"),
    "named.service": ("2.2.4", "a DNS server"),
    "dnsmasq.service": ("2.2.5", "a DNS/DHCP server"),
    "smb.service": ("2.2.6", "an SMB file server"),
    "vsftpd.service": ("2.2.7", "an FTP server"),
    "dovecot.socket": ("2.2.8", "an IMAP/POP3 server"),
    "nfs-server.service": ("2.2.9", "an NFS server"),
    "ypserv.service": ("2.2.10", "a NIS server"),
    "cups.socket": ("2.2.11", "a print server"),
    "rpcbind.socket": ("2.2.12", "the RPC port mapper"),
    "rsyncd.socket": ("2.2.13", "an rsync daemon"),
    "snmpd.service": ("2.2.14", "an SNMP agent"),
    "telnet.socket": ("2.2.15", "a telnet daemon"),
    "tftp.socket": ("2.2.16", "a TFTP daemon"),
    "squid.service": ("2.2.17", "a web proxy"),
    "httpd.socket": ("2.2.18", "a web server"),
    "xinetd.service": ("2.2.19", "a network super-server"),
    "bluetooth.service": ("3.1.3", "the Bluetooth stack"),
}

#: SSM inventory type names this module reads.
APPLICATION_TYPE = "AWS:Application"
SERVICE_TYPE = "AWS:Service"


def _norm(name) -> str:
    return str(name or "").strip().lower()


def _installed(entries: Optional[Sequence[Mapping]]) -> Dict[str, str]:
    """``{package name: version}`` from an ``AWS:Application`` inventory listing."""
    out: Dict[str, str] = {}
    for e in entries or []:
        n = _norm(e.get("Name"))
        if n:
            out[n] = str(e.get("Version") or "")
    return out


def prohibited_packages(instance_id: str,
                        entries: Optional[Sequence[Mapping]]) -> List[dict]:
    """AL2-01 — packages the benchmark says should not be present on a server.

    ONE FINDING PER PACKAGE, not one per host. An operator remediates a package at a
    time, and collapsing twelve prohibited packages into a single finding would give them
    one row to tick off against twelve separate `yum remove` decisions."""
    if entries is None:
        return []
    have = _installed(entries)
    out = []
    for pkg, (rec, what) in sorted(PROHIBITED_PACKAGES.items()):
        if pkg not in have:
            continue
        ver = have[pkg]
        out.append({
            "package": pkg, "recommendation": rec, "version": ver,
            "statement": (
                f"{instance_id} has {pkg}"
                f"{' ' + ver if ver else ''} installed — {what}. It is attack surface "
                f"the host carries whether or not anything uses it: it must be patched, "
                f"it can be started by anything that reaches root, and on a server the "
                f"benchmark's position is that it should not be present at all"),
        })
    return out


def missing_required_packages(instance_id: str,
                              entries: Optional[Sequence[Mapping]]) -> List[dict]:
    """AL2-02 — security packages whose absence removes a control entirely.

    ABSENCE IS ONLY MEANINGFUL IF THE LISTING IS COMPLETE, which is why this returns
    nothing at all for ``entries is None``. An empty inventory and an inventory that was
    never collected produce the same empty list, and reporting the second as "nothing is
    installed" would fail every package on a host nobody has inventoried."""
    if not entries:
        return []
    have = _installed(entries)
    out = []
    for pkg, (rec, why) in sorted(REQUIRED_PACKAGES.items()):
        if pkg in have:
            continue
        out.append({
            "package": pkg, "recommendation": rec,
            "statement": (
                f"{instance_id} does not have {pkg} installed — {why}. The control the "
                f"benchmark asks for is not weakened here, it is absent: there is "
                f"nothing to misconfigure and nothing to review"),
        })
    return out


def prohibited_units(instance_id: str,
                     entries: Optional[Sequence[Mapping]]) -> List[dict]:
    """AL2-03 — a prohibited network service is actually running or enabled.

    STRONGER THAN AL2-01 AND RATED ABOVE IT. An installed package is latent surface; an
    enabled unit is a listening socket right now. Where both fire for the same service
    the operator has one job (remove the package) and two findings that say so at
    different strengths, which is the honest ordering rather than a duplicate."""
    if entries is None:
        return []
    out = []
    for e in entries or []:
        name = _norm(e.get("Name"))
        status = _norm(e.get("Status"))
        start = _norm(e.get("StartType"))
        if name not in PROHIBITED_UNITS:
            continue
        running = status in ("running", "active") or start in ("auto", "enabled")
        if not running:
            continue
        rec, what = PROHIBITED_UNITS[name]
        out.append({
            "unit": name, "recommendation": rec, "status": status or start,
            "statement": (
                f"{instance_id} is running {name} — {what}. Unlike an installed package "
                f"this is a live listening service: it is reachable now by anything the "
                f"security group admits, and it does not wait for somebody to start it"),
        })
    return out


def assessability(instance_id: str, *, ssm_managed: bool,
                  platform: Optional[str],
                  app_entries: Optional[Sequence[Mapping]],
                  svc_entries: Optional[Sequence[Mapping]]) -> dict:
    """AL2-00 — what this host could and could not be assessed for, and why.

    THE REASON THIS EXISTS AT ALL. Every check above returns an empty list when its
    inventory is missing, and an empty list of findings is indistinguishable from a
    compliant host. WINVULN-03 exists for the same reason on the Windows side, and
    CREDEXP-00 on the credential side: a scanner that cannot tell "clean" from "not
    looked at" has already given the operator the wrong answer."""
    if not ssm_managed:
        return {"assessed": False, "statement": (
            f"{instance_id} was NOT assessed against the Amazon Linux benchmark: it is "
            f"not registered with AWS Systems Manager, so no inventory exists to read. "
            f"This is not a pass — nothing about its packages or services is known")}
    if app_entries is None:
        return {"assessed": False, "statement": (
            f"{instance_id} was NOT assessed: it is SSM-managed but has no "
            f"{APPLICATION_TYPE} inventory, which is collected only where an inventory "
            f"association has been set up. Nothing about its installed packages is "
            f"known")}
    note = ""
    if svc_entries is None:
        note = (f" Service state was not assessed: this instance reports no "
                f"{SERVICE_TYPE} inventory, so the enabled-service controls could not "
                f"be decided and only the package controls were")
    return {"assessed": True, "statement": (
        f"{instance_id} assessed from SSM inventory: {len(app_entries)} package(s) "
        f"read.{note}")}


# ══════════════════════════════════════════════════════════════════════════════
# the declarations
# ══════════════════════════════════════════════════════════════════════════════
_SSM_INVENTORY = _P(
    "ssm:ListInventoryEntries",
    "reads the package and service inventory SSM has already collected for an instance. "
    "It is the ONLY read-only path to in-guest state this product has: reading a file "
    "would need ssm:SendCommand, which executes code and is a write")

CHECKS = _cd.register(
    # THE KEY CITES ONE RECOMMENDATION AND THE FINDING CARRIES THE PRECISE ONE. AL2-01
    # decides 27 recommendations — every prohibited package across 2.2, 2.3, 3.1.3 and
    # 1.4.1.7 — and COMPLIANCE_MAP holds a single string per check. Citing the SUBSECTION
    # ("2.2") was the first attempt and it does not resolve: a subsection is not a
    # recommendation, so an auditor following the citation lands on nothing. So the key
    # names a real recommendation this check genuinely decides, and every emitted finding
    # appends the exact recommendation for the package it fired on.
    _C(id="AL2-01", section="AMAZONLINUX", severity="MEDIUM",
       compliance={"CIS-AL2": "2.2.1", "PCI-DSS": "2.2.4",
                   "HIPAA": "164.308(a)(5)(ii)(B)",
                   "SOC2": "CC6.8", "NIST": "CM-7"},
       remediation=(
           "Remove the package rather than disabling its service — a disabled daemon is "
           "one systemctl away from running, and it still has to be patched: "
           "aws ssm send-command --document-name AWS-RunShellScript --instance-ids "
           "<INSTANCE_ID> --parameters 'commands=[\"yum -y remove <PACKAGE>\"]' . "
           "Confirm with aws ssm list-inventory-entries --instance-id <INSTANCE_ID> "
           "--type-name AWS:Application"),
       risk=("The benchmark's position on a server is that these packages should not be "
             "present, not merely that their services should be stopped. An installed "
             "package is a patching obligation whether or not anything uses it, it can "
             "be started by anything that reaches root, and several of them speak "
             "protocols that authenticate in cleartext — telnet, FTP, TFTP and NIS all "
             "put credentials on the wire in the clear. Removing the package removes the "
             "surface; disabling the unit only removes it until somebody, or something, "
             "starts it again."),
       impact=("The host carries network-facing software it does not need, which must be "
               "patched forever and can be started by anything with root."),
       steps=("Confirm what is installed: aws ssm list-inventory-entries --instance-id "
              "<INSTANCE_ID> --type-name AWS:Application",
              "Check nothing depends on the package before removing it: yum deplist "
              "<PACKAGE>",
              "Remove it: yum -y remove <PACKAGE>, or bake a golden AMI without it so "
              "the finding does not return at the next scale-out",
              "Re-collect inventory and confirm the package is gone"),
       permissions=(_SSM_INVENTORY,)),

    _C(id="AL2-02", section="AMAZONLINUX", severity="MEDIUM",
       compliance={"CIS-AL2": "6.2.1.1", "PCI-DSS": "10.2.1",
                   "HIPAA": "164.312(b)", "SOC2": "CC7.2", "NIST": "CM-6"},
       remediation=(
           "Install the missing package and enable its service: aws ssm send-command "
           "--document-name AWS-RunShellScript --instance-ids <INSTANCE_ID> "
           "--parameters 'commands=[\"yum -y install <PACKAGE>\",\"systemctl enable "
           "--now <UNIT>\"]' . Better, bake it into the AMI so new instances start "
           "compliant. Verify with aws ssm list-inventory-entries --instance-id "
           "<INSTANCE_ID> --type-name AWS:Application"),
       risk=("These packages are not hardening settings that can be tuned — they are the "
             "controls themselves. Without auditd the host produces no kernel audit "
             "trail, so the record every detective control assumes exists is not there. "
             "Without rsyslog nothing is forwarded off the host and the logs die with "
             "it, which is exactly what an intruder wants. Without AIDE a replaced "
             "system binary leaves no trace. Without sudo, privilege elevation is a "
             "shared root password and is unattributable. The distinction from a "
             "misconfiguration matters: there is nothing here to review or tighten, "
             "because there is nothing there."),
       impact=("A control the benchmark relies on is absent rather than weak — there is "
               "nothing to misconfigure and nothing to audit."),
       steps=("List what is installed: aws ssm list-inventory-entries --instance-id "
              "<INSTANCE_ID> --type-name AWS:Application",
              "Install the package: yum -y install <PACKAGE>",
              "Enable and start its service where it has one: systemctl enable --now "
              "<UNIT>",
              "Add it to the golden AMI so replacement instances do not regress"),
       permissions=(_SSM_INVENTORY,)),

    _C(id="AL2-03", section="AMAZONLINUX", severity="HIGH",
       compliance={"CIS-AL2": "2.2.1", "PCI-DSS": "2.2.4",
                   "HIPAA": "164.308(a)(5)(ii)(B)", "SOC2": "CC6.6", "NIST": "CM-7"},
       remediation=(
           "Stop and disable the unit, then remove the package that provides it so it "
           "cannot come back: aws ssm send-command --document-name AWS-RunShellScript "
           "--instance-ids <INSTANCE_ID> --parameters 'commands=[\"systemctl disable "
           "--now <UNIT>\",\"yum -y remove <PACKAGE>\"]' . Confirm the listening socket "
           "is gone and re-check the instance's security group, which is what was "
           "admitting traffic to it"),
       risk=("An enabled unit is materially worse than an installed package, which is "
             "why this is rated above AL2-01. The package is latent; the unit is a "
             "listening socket right now, reachable by anything the instance's security "
             "group admits, and it does not wait for anybody to start it. Several of "
             "these speak protocols with no usable authentication — a telnet or TFTP "
             "daemon on a host with a permissive security group is a direct path in, and "
             "rpcbind will enumerate the host's RPC services to anyone who asks. Where "
             "AL2-01 also fires for the same software the operator has one job, remove "
             "the package, and two findings telling them so at different strengths."),
       impact=("A network service the host should not run is listening now and reachable "
               "by whatever the security group admits."),
       steps=("Confirm what is running: aws ssm list-inventory-entries --instance-id "
              "<INSTANCE_ID> --type-name AWS:Service",
              "Stop and disable it: systemctl disable --now <UNIT>",
              "Remove the package that provides it, or it can be restarted: yum -y "
              "remove <PACKAGE>",
              "Re-check the security group that was admitting traffic to the port"),
       permissions=(_SSM_INVENTORY,)),
)
