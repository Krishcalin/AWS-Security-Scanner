#!/usr/bin/env python3
"""Render professional architecture diagrams (PNG) for the OverWatch design doc.
Pure Pillow, 3x supersampled + LANCZOS downscale for crisp anti-aliased output.
Palette matches the Word document (navy / accent blue) + semantic colors."""
import math, os
from PIL import Image, ImageDraw, ImageFont

OUT = os.path.dirname(os.path.abspath(__file__))
S = 3  # supersample factor

# ── palette ───────────────────────────────────────────────────────────────────
WHITE="#FFFFFF"; INK="#1F2A37"; SUBTLE="#5B6672"; NAVY="#143355"; ACCENT="#0E63B3"
LINE="#B9C6D4"; PANEL="#EAF2FB"; PANEL2="#F3F5F7"; PANEL3="#E3ECF5"; PANEL4="#EEF3F8"
CRIM="#C0392B"; CRIMBG="#FBEAE8"; GOLD="#B7791F"; GOLDBG="#FBF3E3"
GREEN="#2E7D5B"; GREENBG="#E6F2EC"; AMBER="#D98A0B"; AMBERBG="#FBF1DE"; PURPLE="#6D4C9F"; PURPBG="#EFE9F6"

def _fp(cands, size):
    for p in cands:
        try: return ImageFont.truetype(p, int(size*S))
        except Exception: pass
    return ImageFont.load_default()
REG=["C:/Windows/Fonts/segoeui.ttf","C:/Windows/Fonts/calibri.ttf","arial.ttf"]
BLD=["C:/Windows/Fonts/segoeuib.ttf","C:/Windows/Fonts/calibrib.ttf","arialbd.ttf"]
SEM=["C:/Windows/Fonts/seguisb.ttf","C:/Windows/Fonts/segoeuisb.ttf"]+BLD
MON=["C:/Windows/Fonts/consola.ttf","cour.ttf"]
def reg(s): return _fp(REG,s)
def bld(s): return _fp(BLD,s)
def sem(s): return _fp(SEM,s)
def mon(s): return _fp(MON,s)

class Canvas:
    def __init__(self, w, h, bg=WHITE):
        self.w, self.h = w, h
        self.im = Image.new("RGB", (w*S, h*S), bg)
        self.d = ImageDraw.Draw(self.im)
    def rect(self, x, y, w, h, fill=None, outline=LINE, width=1.4, radius=12):
        self.d.rounded_rectangle([x*S, y*S, (x+w)*S, (y+h)*S], radius=int(radius*S),
                                 fill=fill, outline=outline, width=max(1, int(width*S)))
    def text(self, x, y, s, f, fill=INK, anchor="lm", spacing=4):
        self.d.text((x*S, y*S), s, font=f, fill=fill, anchor=anchor, spacing=spacing*S)
    def mtext(self, cx, y, lines, f, fill=INK, lh=None, anchor="mm"):
        lh = lh or (f.size/S*1.35)
        for i, ln in enumerate(lines):
            self.text(cx, y + i*lh, ln, f, fill=fill, anchor=anchor)
    def line(self, x1, y1, x2, y2, fill=ACCENT, width=2.0):
        self.d.line([x1*S, y1*S, x2*S, y2*S], fill=fill, width=max(1, int(width*S)))
    def dline(self, x1, y1, x2, y2, fill=SUBTLE, width=1.6, dash=9, gap=7):
        dx, dy = x2-x1, y2-y1; L = math.hypot(dx, dy) or 1; ux, uy = dx/L, dy/L
        n = int(L//(dash+gap))+1; t = 0
        for _ in range(n):
            a=t; b=min(t+dash, L)
            self.d.line([(x1+ux*a)*S,(y1+uy*a)*S,(x1+ux*b)*S,(y1+uy*b)*S], fill=fill, width=max(1,int(width*S)))
            t += dash+gap
    def _head(self, x, y, ang, fill, sz=11):
        p=[(x,y),(x-sz*math.cos(ang-0.42), y-sz*math.sin(ang-0.42)),(x-sz*math.cos(ang+0.42), y-sz*math.sin(ang+0.42))]
        self.d.polygon([(px*S,py*S) for px,py in p], fill=fill)
    def arrow(self, x1, y1, x2, y2, fill=ACCENT, width=2.2, dashed=False, head=11):
        ang=math.atan2(y2-y1, x2-x1); bx,by=x2-head*0.85*math.cos(ang), y2-head*0.85*math.sin(ang)
        (self.dline if dashed else self.line)(x1,y1,bx,by, fill=fill, width=width)
        self._head(x2, y2, ang, fill, head)
    def save(self, name):
        self.im.resize((self.w, self.h), Image.LANCZOS).save(os.path.join(OUT, name))
        return name

def box(c, x, y, w, h, title, subtitle=None, fill=PANEL, border=ACCENT, tcol=NAVY,
        tf=None, sf=None, radius=12, bw=1.6):
    c.rect(x, y, w, h, fill=fill, outline=border, width=bw, radius=radius)
    tf = tf or sem(15); sf = sf or reg(11.5)
    if subtitle:
        c.text(x+w/2, y+h/2-9, title, tf, fill=tcol, anchor="mm")
        if isinstance(subtitle, list):
            c.mtext(x+w/2, y+h/2+11, subtitle, sf, fill=SUBTLE)
        else:
            c.text(x+w/2, y+h/2+11, subtitle, sf, fill=SUBTLE, anchor="mm")
    else:
        c.text(x+w/2, y+h/2, title, tf, fill=tcol, anchor="mm")

def chip(c, x, y, w, h, label, fill=WHITE, border=LINE, tcol=INK, fs=11):
    c.rect(x, y, w, h, fill=fill, outline=border, width=1.2, radius=8)
    c.text(x+w/2, y+h/2, label, sem(fs), fill=tcol, anchor="mm")

def title_block(c, t, sub):
    c.text(40, 40, t, bld(23), fill=NAVY, anchor="lm")
    c.line(40, 66, c.w-40, 66, fill=LINE, width=1.2)
    if sub: c.text(40, 84, sub, reg(12), fill=SUBTLE, anchor="lm")

# ═══════════════════════════════════════════════════════════════════════════════
def d1_stack():
    c = Canvas(1520, 1000)
    title_block(c, "Figure 1 — Logical Architecture (three tiers)",
                "React console over a fail-closed control plane over a pure scanning engine")
    X, W = 70, 1380
    def tier(y, h, name, fill, chips_rows, cf):
        c.rect(X, y, W, h, fill=fill, outline=ACCENT, width=1.8, radius=14)
        c.text(X+22, y+26, name, bld(15), fill=NAVY, anchor="lm")
        cy = y+58
        for row in chips_rows:
            n=len(row); gap=14; cw=(W-44-gap*(n-1))/n; cx=X+22
            for lab in row:
                chip(c, cx, cy, cw, 40, lab, fill=WHITE, border=cf, fs=11); cx+=cw+gap
            cy += 52
    tier(112, 168, "WEB CONSOLE — React SPA  (LIVE hub  ·  SAMPLE mirror + parity fixture)", PANEL,
         [["Overview","Attack Paths","Findings","Vulnerabilities","Runtime","Data"],
          ["Supply Chain","Registries","Query (WQL)","Compliance","Remediation","Reports"]], "#9EC1E6")
    c.arrow(X+W/2, 280, X+W/2, 312, fill=ACCENT, width=2.6)
    c.text(X+W/2+14, 296, "HTTPS · fail-closed auth (IdP/JWT)", reg(10.5), fill=SUBTLE, anchor="lm")
    tier(318, 168, "HOSTED CONTROL PLANE — FastAPI  ·  PlatformService  ·  workspace-scoped RBAC", PANEL3,
         [["Onboarding","Scheduler","Workspaces / RBAC","Metering (MSSP)"],
          ["Notif. connectors","WQL / Controls / Policy","Registry connectors","HTTP API"]], "#A9C4DF")
    c.arrow(X+W/2, 486, X+W/2, 518, fill=ACCENT, width=2.6)
    c.text(X+W/2+14, 502, "in-process (injected seams)", reg(10.5), fill=SUBTLE, anchor="lm")
    tier(524, 250, "SCANNING ENGINE — pure, boto3-injected, offline-testable", PANEL4,
         [["Collect","Graph build","Exposure / L7","Deep-plane","Correlate","Persist"],
          ["Eff-perm","CIEM","Side-scan CWPP","KSPM / KIEM","DSPM","AI-SPM"],
          ["CDR / EDR","Malware","Forensics","Copilot (RAG)","SBOM / VEX","Registry pull"]], "#B7C6D6")
    c.arrow(X+W/2, 786, X+W/2, 818, fill=ACCENT, width=2.6)
    y=824; gap=18; bw=(W-gap*3)/4
    for i,(t,s) in enumerate([("boto3 — AWS APIs","read-only, per-account"),
                              ("State store","SQLite / PostgreSQL"),
                              ("Vulnerability feed","BYO / local, signed"),
                              ("Kubernetes API","read-only (optional)")]):
        box(c, X+i*(bw+gap), y, bw, 96, t, s, fill=PANEL2, border=LINE, tf=sem(13), sf=reg(10.5))
    c.text(X, y+130, "Charter:  agentless  ·  read-only  ·  self-hosted  ·  AWS-first  ·  zero-telemetry / air-gap",
           sem(12), fill=NAVY, anchor="lm")
    return c.save("fig1_architecture.png")

def d2_topology():
    c = Canvas(1560, 950)
    title_block(c, "Figure 2 — Runtime Topology (hub in the security VPC)",
                "One hardened container on a private subnet; AWS reached via VPC endpoints; spokes via AssumeRole")
    # actor + ALB (left)
    box(c, 40, 150, 190, 74, "Analyst / Admin", "browser (internal)", fill=PANEL2, border=LINE, tf=sem(13), sf=reg(10))
    box(c, 40, 250, 190, 84, "Internal ALB", ["TLS termination","+ IdP / JWT"], fill=PANEL, border=ACCENT, tf=sem(13), sf=reg(10))
    c.arrow(135, 224, 135, 250, fill=ACCENT, width=2.2)
    # Security VPC
    c.rect(270, 120, 690, 790, fill="#F7FAFD", outline=ACCENT, width=2.0, radius=16)
    c.text(292, 146, "SECURITY VPC", bld(14), fill=NAVY, anchor="lm")
    c.rect(300, 176, 630, 300, fill=WHITE, outline=LINE, width=1.4, radius=12)
    c.text(320, 200, "Private subnet (no public route)", sem(12), fill=SUBTLE, anchor="lm")
    box(c, 330, 226, 570, 224, "OverWatch Hub — EC2 (container)",
        ["uvicorn :8080  ·  non-root image","KMS-encrypted state volume  ·  IMDSv2 required",
         "Security group: inbound from ALB only","Instance profile → CnappHubRole"],
        fill=PANEL, border=ACCENT, tf=sem(15), sf=reg(11))
    c.arrow(230, 292, 330, 320, fill=ACCENT, width=2.2)                 # ALB -> hub
    box(c, 300, 500, 630, 176, "VPC Endpoints (interface + S3 gateway)",
        ["sts · ec2 · iam · s3 · logs · kms · config","secretsmanager · ssm · cloudtrail",
         "guardduty · securityhub · access-analyzer · eks"],
        fill=PANEL3, border="#A9C4DF", tf=sem(13.5), sf=reg(11))
    c.arrow(615, 476, 615, 500, fill=ACCENT, width=2.0)                 # hub -> endpoints
    c.rect(300, 700, 630, 180, fill="#FAFBFC", outline=LINE, width=1.2, radius=12)
    c.text(320, 726, "No public-internet egress  ·  zero telemetry", sem(12), fill=GREEN, anchor="lm")
    c.text(320, 756, "Every outbound call is an AWS API to the customer's own accounts,", reg(11), fill=SUBTLE, anchor="lm")
    c.text(320, 780, "or an operator-configured seam (K8s / notifications / registry).", reg(11), fill=SUBTLE, anchor="lm")
    c.text(320, 816, "Air-gap: one offline bundle crosses the boundary (docs/AIRGAP_RUNBOOK.md).", reg(11), fill=SUBTLE, anchor="lm")
    # right column — spokes (upper, red AssumeRole) then AWS APIs (lower, blue via endpoints): no crossing
    c.text(1010, 134, "Audited spoke accounts  —  sts:AssumeRole + ExternalId (read-only)", bld(12), fill=NAVY, anchor="lm")
    for i in range(3):
        yy = 152 + i*126
        box(c, 1010, yy, 500, 110, f"Spoke account {i+1}", ["CnappScannerRole — read-only","(SecurityAudit + explicit reads)"],
            fill=WHITE, border=GREEN if i == 0 else LINE, tf=sem(13), sf=reg(10.5))
        c.arrow(900, 392, 1010, yy+55, fill=CRIM, width=1.8, dashed=True, head=10)   # hub -> spoke
    box(c, 1010, 562, 500, 130, "AWS Service APIs", ["Control-plane APIs, read-only","reached only via the VPC endpoints"],
        fill=PANEL2, border=LINE, tf=sem(15), sf=reg(11))
    c.arrow(930, 604, 1010, 624, fill=ACCENT, width=2.2)                # endpoints -> AWS APIs
    c.text(944, 590, "via endpoints", reg(9.5), fill=SUBTLE, anchor="lm")
    return c.save("fig2_topology.png")

def d3_pipeline():
    c = Canvas(1560, 560)
    title_block(c, "Figure 3 — Scan Pipeline & Engine Fan-out",
                "Read-only collect → graph → reachability → deep-plane → correlate; specialized engines read the graph")
    stages=[("Collect","44 sections, boto3"),("Graph build","typed nodes + edges"),
            ("Exposure & L7","4-gate reachability"),("Deep-plane","Inspector/Macie/GD/AA"),
            ("Correlate","attack paths + choke pts"),("Persist","findings · posture · drift")]
    X=60; W=(1440-(len(stages)-1)*26)/len(stages); y=130
    cxs=[]
    for i,(t,s) in enumerate(stages):
        x=X+i*(W+26); cxs.append(x+W/2)
        fill=PANEL if i not in (1,4) else PANEL3
        box(c, x, y, W, 96, t, s, fill=fill, border=ACCENT if i in (1,4) else "#9EC1E6",
            tf=sem(13.5), sf=reg(10), bw=2.2 if i in (1,4) else 1.4)
        if i: c.arrow(x-26, y+48, x-3, y+48, fill=ACCENT, width=2.4, head=10)
    # graph spine
    gx = cxs[1]
    c.text(60, 300, "Specialized engines read the security graph (annotations enrich; only E_PATH edges are traversed):",
           sem(12), fill=NAVY, anchor="lm")
    eng=[["Effective-permissions (∩ boundary ∩ SCP)","CIEM / least-privilege","Side-scan CWPP (OS + deps + secrets)"],
         ["KSPM / KIEM (EKS + RBAC + IRSA)","DSPM (crown-jewel data) + AI-SPM","CDR / EDR / malware ingest (THREAT_ON)"],
         ["Cloud-forensics timeline","Supply chain: SBOM / diff / license / VEX","Grounded-RAG copilot"]]
    yy=336; gap=18
    for row in eng:
        n=len(row); cw=(1440-gap*(n-1))/n; x=60
        for lab in row:
            chip(c, x, yy, cw, 46, lab, fill=WHITE, border=LINE, fs=11); x+=cw+gap
        yy+=58
    # link graph stage down to the engines band
    c.dline(gx, y+96, gx, 322, fill="#9EC1E6", width=1.6)
    c.arrow(gx, 322, gx, 330, fill="#9EC1E6", width=1.6, head=8)
    c.arrow(cxs[4], y+96, cxs[4], 322, fill="#9EC1E6", width=1.6, dashed=True, head=8)
    return c.save("fig3_pipeline.png")

def d4_graph():
    c = Canvas(1560, 770)
    title_block(c, "Figure 4 — The Attack-Path Graph (the differentiator)",
                "Rank the entry→crown-jewel chain; a toxic combination is a conjunction, so a missing factor collapses the score")
    def node(x,y,w,h,t,s,fill,border,tcol=NAVY):
        box(c,x,y,w,h,t,s,fill=fill,border=border,tf=sem(13),sf=reg(9.5),tcol=tcol,radius=14)
        return (x,y,w,h)
    yc=300; h=92
    n0=node(60, yc, 150, h, "Internet", "any source", CRIMBG, CRIM, CRIM)
    n1=node(272, yc, 176, h, "L7 front", "ALB / CloudFront", PANEL, ACCENT)
    n2=node(510, yc, 186, h, "Workload", "EC2 / container", PANEL, ACCENT)
    n3=node(758, yc, 176, h, "IAM role", "instance profile", PANEL, ACCENT)
    n4=node(996, yc, 186, h, "Admin role", "privilege escalation", PANEL, ACCENT)
    n5=node(1244, yc, 216, h, "S3 crown jewel", "sensitive data", GOLDBG, GOLD, GOLD)
    def edge(a,b,label):
        x1=a[0]+a[2]; x2=b[0]; y=yc+h/2
        c.arrow(x1, y, x2-3, y, fill=CRIM, width=3.0, head=13)
        c.text((x1+x2)/2, yc-20, label, sem(10), fill=CRIM, anchor="mm")   # above the boxes
    edge(n0,n1,"EXPOSED_TO"); edge(n1,n2,"TARGETS"); edge(n2,n3,"HAS_ROLE")
    edge(n3,n4,"CAN_ASSUME"); edge(n4,n5,"CAN_READ_DATA")
    # crown secret satellite
    box(c, 1290, yc+150, 170, 66, "Secret", "SSM / Secrets Mgr", fill=GOLDBG, border=GOLD, tf=sem(12), sf=reg(9), tcol=GOLD)
    c.arrow(1352, yc+h, 1352, yc+150, fill=GOLD, width=2.0, head=9)
    c.text(1368, yc+128, "CAN_READ_DATA", sem(9.5), fill=GOLD, anchor="lm")
    # annotations (dashed, out of E_PATH)
    box(c, 470, yc-165, 230, 74, "Vulnerability (CVE)", ["exploitable · KEV/EPSS"], fill=AMBERBG, border=AMBER, tf=sem(12), sf=reg(9.5), tcol=AMBER)
    c.arrow(585, yc-91, 590, yc-3, fill=AMBER, width=1.8, dashed=True, head=9)
    c.text(600, yc-48, "HAS_VULN", sem(9.5), fill=AMBER, anchor="lm")
    box(c, 960, yc-165, 240, 74, "Threat detection", ["EDR / GuardDuty / malware"], fill=PURPBG, border=PURPLE, tf=sem(12), sf=reg(9.5), tcol=PURPLE)
    c.arrow(1075, yc-91, 1080, yc-3, fill=PURPLE, width=1.8, dashed=True, head=9)
    c.text(1090, yc-48, "THREAT_ON", sem(9.5), fill=PURPLE, anchor="lm")
    # score tag
    c.rect(60, yc+150, 380, 110, fill=CRIMBG, outline=CRIM, width=1.8, radius=12)
    c.text(80, yc+178, "Ranked attack path", bld(14), fill=CRIM, anchor="lm")
    c.text(80, yc+206, "exposure × exploitability × privilege × data-path", reg(11), fill=INK, anchor="lm")
    c.text(80, yc+230, "score = gated-multiplicative, MAX per jewel", reg(11), fill=INK, anchor="lm")
    c.text(410, yc+178, "87", bld(30), fill=CRIM, anchor="rm")
    # legend
    ly=710
    c.line(80, ly, 150, ly, fill=CRIM, width=3.0); c.arrow(150, ly, 156, ly, fill=CRIM, width=3.0, head=11)
    c.text(168, ly, "Traversable edge (E_PATH) — walked as a hop", reg(11.5), fill=INK, anchor="lm")
    c.dline(640, ly, 716, ly, fill=SUBTLE, width=1.8); c.arrow(716, ly, 722, ly, fill=SUBTLE, width=1.8, head=9)
    c.text(734, ly, "Annotation — enriches a node, never a hop (frozen correlator)", reg(11.5), fill=INK, anchor="lm")
    return c.save("fig4_attackpath.png")

def d5_egress():
    c = Canvas(1520, 720)
    title_block(c, "Figure 5 — Egress Containment (zero-telemetry)",
                "Only three files may open a socket; enforced by a recursive-AST tripwire test")
    box(c, 600, 250, 320, 150, "OverWatch", ["engine + control plane","(pure, injected seams)"],
        fill=NAVY, border=NAVY, tf=bld(18), sf=reg(11), tcol=WHITE)
    # allowlisted egress (right)
    allow=[("aws_kube.py","Kubernetes API (read-only)"),
           ("cnapp_connectors.py","Operator's OWN tools (Jira/Slack/PagerDuty/…)"),
           ("aws_layer_fetch.py","Registry layer blobs (ECR presign + non-AWS OCI)")]
    for i,(f,p) in enumerate(allow):
        yy=140+i*116
        box(c, 1060, yy, 400, 92, f, [p], fill=PANEL, border=ACCENT, tf=mon(12.5), sf=reg(10), tcol=NAVY)
        c.arrow(920, 325, 1060, yy+46, fill=ACCENT, width=2.0, head=10)
    c.text(1060, 512, "Each has a single documented purpose · re-checked on every redirect", reg(10.5), fill=SUBTLE, anchor="lm")
    # AWS (left, the bulk)
    c.rect(60, 190, 470, 210, fill=GREENBG, outline=GREEN, width=1.8, radius=14)
    c.text(90, 226, "Customer's OWN AWS accounts", bld(15), fill=GREEN, anchor="lm")
    c.text(90, 262, "boto3 — read-only control-plane calls", reg(12), fill=INK, anchor="lm")
    c.text(90, 290, "the overwhelming majority of all egress;", reg(11.5), fill=SUBTLE, anchor="lm")
    c.text(90, 314, "never a data-plane / object read", reg(11.5), fill=SUBTLE, anchor="lm")
    c.text(90, 350, "assumed per-account, expires after the scan", reg(11.5), fill=SUBTLE, anchor="lm")
    c.arrow(600, 325, 530, 295, fill=GREEN, width=2.4, head=11)
    # blocked (bottom)
    bx,by=600,530
    c.rect(bx, by, 320, 120, fill=CRIMBG, outline=CRIM, width=1.8, radius=14)
    c.text(bx+160, by+34, "Internet · telemetry · phone-home", sem(12.5), fill=CRIM, anchor="mm")
    c.text(bx+160, by+68, "BLOCKED", bld(20), fill=CRIM, anchor="mm")
    c.arrow(760, 400, 760, 530, fill=CRIM, width=2.2, dashed=True, head=11)
    c.d.ellipse([(742)*S,(447)*S,(778)*S,(483)*S], outline=CRIM, width=int(2.4*S))   # prohibition
    c.line(748, 453, 772, 477, fill=CRIM, width=2.4)
    c.text(60, 682, "Guard: tests/test_zero_telemetry.py — a recursive-AST scan of every shipped module fails CI if any other file holds a network primitive.",
           reg(11), fill=SUBTLE, anchor="lm")
    return c.save("fig5_egress.png")

if __name__ == "__main__":
    for fn in (d1_stack, d2_topology, d3_pipeline, d4_graph, d5_egress):
        name = fn()
        im = Image.open(os.path.join(OUT, name))
        print(f"{name:26s} {im.size[0]}x{im.size[1]}")
