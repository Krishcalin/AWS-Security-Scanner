#!/usr/bin/env python3
"""Render professional architecture diagrams (PNG) for the OverWatch design doc.
Pure Pillow, 3x supersampled + LANCZOS downscale for crisp anti-aliased output.
Fonts are sized LARGE relative to canvas width so text stays legible when the figure
is embedded at ~6.4in in Word. Palette matches the document (navy / accent blue)."""
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
    try: return ImageFont.load_default(int(size*S))
    except Exception: return ImageFont.load_default()
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
    def rect(self, x, y, w, h, fill=None, outline=LINE, width=1.8, radius=14):
        self.d.rounded_rectangle([x*S, y*S, (x+w)*S, (y+h)*S], radius=int(radius*S),
                                 fill=fill, outline=outline, width=max(1, int(width*S)))
    def text(self, x, y, s, f, fill=INK, anchor="lm", spacing=4):
        self.d.text((x*S, y*S), s, font=f, fill=fill, anchor=anchor, spacing=spacing*S)
    def mtext(self, cx, y, lines, f, fill=INK, lh=None, anchor="mm"):
        lh = lh or (f.size/S*1.4)
        for i, ln in enumerate(lines):
            self.text(cx, y + i*lh, ln, f, fill=fill, anchor=anchor)
    def line(self, x1, y1, x2, y2, fill=ACCENT, width=3.0):
        self.d.line([x1*S, y1*S, x2*S, y2*S], fill=fill, width=max(1, int(width*S)))
    def dline(self, x1, y1, x2, y2, fill=SUBTLE, width=2.4, dash=11, gap=8):
        dx, dy = x2-x1, y2-y1; L = math.hypot(dx, dy) or 1; ux, uy = dx/L, dy/L
        n = int(L//(dash+gap))+1; t = 0
        for _ in range(n):
            a=t; b=min(t+dash, L)
            self.d.line([(x1+ux*a)*S,(y1+uy*a)*S,(x1+ux*b)*S,(y1+uy*b)*S], fill=fill, width=max(1,int(width*S)))
            t += dash+gap
    def _head(self, x, y, ang, fill, sz=16):
        p=[(x,y),(x-sz*math.cos(ang-0.42), y-sz*math.sin(ang-0.42)),(x-sz*math.cos(ang+0.42), y-sz*math.sin(ang+0.42))]
        self.d.polygon([(px*S,py*S) for px,py in p], fill=fill)
    def arrow(self, x1, y1, x2, y2, fill=ACCENT, width=3.2, dashed=False, head=16):
        ang=math.atan2(y2-y1, x2-x1); bx,by=x2-head*0.85*math.cos(ang), y2-head*0.85*math.sin(ang)
        (self.dline if dashed else self.line)(x1,y1,bx,by, fill=fill, width=width)
        self._head(x2, y2, ang, fill, head)
    def save(self, name):
        self.im.resize((self.w, self.h), Image.LANCZOS).save(os.path.join(OUT, name))
        return name

def box(c, x, y, w, h, title, subtitle=None, fill=PANEL, border=ACCENT, tcol=NAVY,
        tf=None, sf=None, radius=14, bw=2.0):
    c.rect(x, y, w, h, fill=fill, outline=border, width=bw, radius=radius)
    tf = tf or sem(28); sf = sf or reg(22)
    if subtitle:
        off = tf.size/S*0.62
        c.text(x+w/2, y+h/2-off, title, tf, fill=tcol, anchor="mm")
        if isinstance(subtitle, list):
            c.mtext(x+w/2, y+h/2+off*0.75, subtitle, sf, fill=SUBTLE)
        else:
            c.text(x+w/2, y+h/2+off, subtitle, sf, fill=SUBTLE, anchor="mm")
    else:
        c.text(x+w/2, y+h/2, title, tf, fill=tcol, anchor="mm")

def chip(c, x, y, w, h, label, fill=WHITE, border=LINE, tcol=INK, fs=24):
    c.rect(x, y, w, h, fill=fill, outline=border, width=1.6, radius=10)
    c.text(x+w/2, y+h/2, label, sem(fs), fill=tcol, anchor="mm")

def title_block(c, t, sub):
    c.text(56, 52, t, bld(38), fill=NAVY, anchor="lm")
    c.line(56, 88, c.w-56, 88, fill=LINE, width=1.6)
    if sub: c.text(56, 116, sub, reg(25), fill=SUBTLE, anchor="lm")

# ═══════════════════════════════════════════════════════════════════════════════
def d1_stack():
    c = Canvas(1380, 1210)
    title_block(c, "Figure 1 — Logical Architecture (three tiers)",
                "A React console over a fail-closed control plane over a pure scanning engine")
    X, W = 60, 1260
    def tier(y, name, chip_rows, cf, fill, chip_h=58, rgap=16):
        rows = len(chip_rows)
        h = 70 + rows*(chip_h+rgap)
        c.rect(X, y, W, h, fill=fill, outline=ACCENT, width=2.2, radius=16)
        c.text(X+26, y+36, name, bld(26), fill=NAVY, anchor="lm")
        cy = y+72
        for row in chip_rows:
            n=len(row); gap=16; cw=(W-52-gap*(n-1))/n; cx=X+26
            for lab in row:
                chip(c, cx, cy, cw, chip_h, lab, fill=WHITE, border=cf, fs=23); cx+=cw+gap
            cy += chip_h+rgap
        return y+h
    y = 152
    y = tier(y, "WEB CONSOLE — React SPA   (LIVE hub · SAMPLE mirror + parity fixture)",
             [["Overview","Attack Paths","Findings","Vulnerabilities"],
              ["Runtime","Data Security","Supply Chain","Registries"],
              ["Query (WQL)","Compliance","Remediation","Reports"]], "#9EC1E6", PANEL)
    c.arrow(X+W/2, y+4, X+W/2, y+42, fill=ACCENT, width=3.2); c.text(X+W/2+18, y+24, "HTTPS · fail-closed auth (IdP/JWT)", reg(21), fill=SUBTLE, anchor="lm")
    y += 50
    y = tier(y, "HOSTED CONTROL PLANE — FastAPI · PlatformService · workspace-scoped RBAC",
             [["Onboarding","Scheduler","Workspaces / RBAC","Metering (MSSP)"],
              ["Notify connectors","WQL / Controls / Policy","Registry connectors","HTTP API"]], "#A9C4DF", PANEL3)
    c.arrow(X+W/2, y+4, X+W/2, y+42, fill=ACCENT, width=3.2); c.text(X+W/2+18, y+24, "in-process (injected seams)", reg(21), fill=SUBTLE, anchor="lm")
    y += 50
    y = tier(y, "SCANNING ENGINE — pure, boto3-injected, offline-testable",
             [["Collect","Graph build","Exposure / L7","Deep-plane"],
              ["Correlate","Eff-perm / CIEM","Side-scan / KSPM / DSPM","Ingest · Forensics · Copilot"]], "#B7C6D6", PANEL4)
    c.arrow(X+W/2, y+4, X+W/2, y+42, fill=ACCENT, width=3.2)
    y += 50
    gap=20; bw=(W-gap*3)/4
    for i,(t,s) in enumerate([("boto3 — AWS APIs","read-only, per-account"),
                              ("State store","SQLite / PostgreSQL"),
                              ("Vulnerability feed","BYO / local, signed"),
                              ("Kubernetes API","read-only (optional)")]):
        box(c, X+i*(bw+gap), y, bw, 110, t, s, fill=PANEL2, border=LINE, tf=sem(24), sf=reg(19))
    c.text(X, y+146, "Charter:  agentless · read-only · self-hosted · AWS-first · zero-telemetry / air-gap",
           sem(23), fill=NAVY, anchor="lm")
    return c.save("fig1_architecture.png")

def d2_topology():
    c = Canvas(1460, 980)
    title_block(c, "Figure 2 — Runtime Topology (hub in the security VPC)",
                "One hardened container on a private subnet; AWS via VPC endpoints; spokes via AssumeRole")
    box(c, 40, 214, 200, 90, "Analyst / Admin", "browser (internal)", fill=PANEL2, border=LINE, tf=sem(24), sf=reg(19))
    box(c, 40, 326, 200, 98, "Internal ALB", ["TLS termination","+ IdP / JWT"], fill=PANEL, border=ACCENT, tf=sem(24), sf=reg(19))
    c.arrow(140, 304, 140, 326, fill=ACCENT, width=3.0)
    c.rect(268, 178, 620, 752, fill="#F7FAFD", outline=ACCENT, width=2.4, radius=18)
    c.text(292, 210, "SECURITY  VPC", bld(25), fill=NAVY, anchor="lm")
    c.rect(298, 240, 560, 300, fill=WHITE, outline=LINE, width=1.6, radius=12)
    c.text(320, 270, "Private subnet (no public route)", sem(21), fill=SUBTLE, anchor="lm")
    box(c, 326, 296, 504, 226, "OverWatch Hub — EC2 (container)",
        ["uvicorn :8080 · non-root image","KMS-encrypted volume · IMDSv2","SG: inbound from ALB only",
         "Instance profile → CnappHubRole"], fill=PANEL, border=ACCENT, tf=sem(25), sf=reg(20))
    c.arrow(240, 372, 326, 400, fill=ACCENT, width=3.0)
    box(c, 298, 566, 560, 170, "VPC Endpoints (interface + S3 gateway)",
        ["sts · ec2 · iam · s3 · logs · kms · config","secretsmanager · ssm · cloudtrail",
         "guardduty · securityhub · access-analyzer · eks"], fill=PANEL3, border="#A9C4DF", tf=sem(23), sf=reg(19))
    c.arrow(578, 540, 578, 566, fill=ACCENT, width=2.8)
    c.rect(298, 758, 560, 150, fill="#FAFBFC", outline=LINE, width=1.4, radius=12)
    c.text(320, 788, "No public-internet egress · zero telemetry", sem(22), fill=GREEN, anchor="lm")
    c.text(320, 822, "Outbound = AWS APIs to the customer's own accounts,", reg(19), fill=SUBTLE, anchor="lm")
    c.text(320, 850, "or an operator-configured seam (K8s / notify / registry).", reg(19), fill=SUBTLE, anchor="lm")
    c.text(320, 884, "Air-gap: one offline bundle crosses the boundary.", reg(19), fill=SUBTLE, anchor="lm")
    c.text(920, 190, "Audited spoke accounts", bld(22), fill=NAVY, anchor="lm")
    c.text(920, 216, "sts:AssumeRole + ExternalId (read-only)", reg(18), fill=SUBTLE, anchor="lm")
    for i in range(3):
        yy = 238 + i*126
        box(c, 920, yy, 500, 110, f"Spoke account {i+1}", "CnappScannerRole — read-only",
            fill=WHITE, border=GREEN if i == 0 else LINE, tf=sem(24), sf=reg(19))
        c.arrow(830, 462, 920, yy+55, fill=CRIM, width=2.6, dashed=True, head=14)
    box(c, 920, 622, 500, 142, "AWS Service APIs", ["Control-plane APIs, read-only","reached only via the VPC endpoints"],
        fill=PANEL2, border=LINE, tf=sem(25), sf=reg(19))
    c.arrow(858, 668, 920, 686, fill=ACCENT, width=3.0)
    c.text(866, 650, "via endpoints", reg(18), fill=SUBTLE, anchor="lm")
    return c.save("fig2_topology.png")

def d3_pipeline():
    c = Canvas(1460, 720)
    title_block(c, "Figure 3 — Scan Pipeline & Engine Fan-out",
                "Read-only collect → graph → reachability → deep-plane → correlate; engines read the graph")
    stages=[("Collect","44 sections"),("Graph build","nodes + edges"),
            ("Exposure & L7","reachability"),("Deep-plane","Inspector/Macie"),
            ("Correlate","paths + chokes"),("Persist","posture · drift")]
    X=60; W=(1340-(len(stages)-1)*22)/len(stages); y=170
    cxs=[]
    for i,(t,s) in enumerate(stages):
        x=X+i*(W+22); cxs.append(x+W/2)
        hot = i in (1,4)
        box(c, x, y, W, 128, t, s, fill=PANEL3 if hot else PANEL, border=ACCENT if hot else "#9EC1E6",
            tf=sem(24), sf=reg(18), bw=2.6 if hot else 1.8)
        if i: c.arrow(x-22, y+64, x-3, y+64, fill=ACCENT, width=3.0, head=13)
    c.text(60, 356, "Specialized engines read the security graph (annotations enrich; only E_PATH edges are traversed):",
           sem(22), fill=NAVY, anchor="lm")
    eng=[["Effective-permissions (∩ boundary ∩ SCP)","CIEM / least-privilege","Side-scan CWPP (OS + deps + secrets)"],
         ["KSPM / KIEM (EKS + RBAC + IRSA)","DSPM + AI-SPM","CDR / EDR / malware ingest (THREAT_ON)"],
         ["Cloud-forensics timeline","Supply chain: SBOM / license / VEX","Grounded-RAG copilot"]]
    yy=392; gap=20
    for row in eng:
        n=len(row); cw=(1340-gap*(n-1))/n; x=60
        for lab in row:
            chip(c, x, yy, cw, 58, lab, fill=WHITE, border=LINE, fs=21); x+=cw+gap
        yy+=72
    return c.save("fig3_pipeline.png")

def d4_graph():
    c = Canvas(1520, 820)
    title_block(c, "Figure 4 — The Attack-Path Graph (the differentiator)",
                "Rank the entry→crown-jewel chain; a toxic combination is a conjunction — a missing factor collapses the score")
    def node(x,y,w,h,t,s,fill,border,tcol=NAVY):
        box(c,x,y,w,h,t,s,fill=fill,border=border,tf=sem(23),sf=reg(17),tcol=tcol,radius=16)
        return (x,y,w,h)
    yc=330; h=110
    n0=node(56, yc, 168, h, "Internet", "any source", CRIMBG, CRIM, CRIM)
    n1=node(286, yc, 190, h, "L7 front", "ALB / CloudFront", PANEL, ACCENT)
    n2=node(536, yc, 198, h, "Workload", "EC2 / container", PANEL, ACCENT)
    n3=node(794, yc, 188, h, "IAM role", "instance profile", PANEL, ACCENT)
    n4=node(1042, yc, 198, h, "Admin role", "privesc", PANEL, ACCENT)
    n5=node(1300, yc, 164, h, "Crown jewel", "S3 · sensitive", GOLDBG, GOLD, GOLD)
    def edge(a,b,label):
        x1=a[0]+a[2]; x2=b[0]; y=yc+h/2
        c.arrow(x1, y, x2-3, y, fill=CRIM, width=3.6, head=16)
        c.text((x1+x2)/2, yc-24, label, sem(18), fill=CRIM, anchor="mm")
    edge(n0,n1,"EXPOSED_TO"); edge(n1,n2,"TARGETS"); edge(n2,n3,"HAS_ROLE")
    edge(n3,n4,"CAN_ASSUME"); edge(n4,n5,"CAN_READ_DATA")
    box(c, 1300, yc+166, 164, 76, "Secret", "SSM / Secrets", fill=GOLDBG, border=GOLD, tf=sem(21), sf=reg(16), tcol=GOLD)
    c.arrow(1382, yc+h, 1382, yc+166, fill=GOLD, width=2.6, head=12)
    box(c, 492, yc-192, 250, 86, "Vulnerability (CVE)", "exploitable · KEV/EPSS", fill=AMBERBG, border=AMBER, tf=sem(20), sf=reg(15), tcol=AMBER)
    c.arrow(617, yc-106, 622, yc-3, fill=AMBER, width=2.4, dashed=True, head=12); c.text(634, yc-58, "HAS_VULN", sem(16), fill=AMBER, anchor="lm")
    box(c, 1000, yc-192, 262, 86, "Threat detection", "EDR / GuardDuty", fill=PURPBG, border=PURPLE, tf=sem(20), sf=reg(15), tcol=PURPLE)
    c.arrow(1131, yc-106, 1136, yc-3, fill=PURPLE, width=2.4, dashed=True, head=12); c.text(1148, yc-58, "THREAT_ON", sem(16), fill=PURPLE, anchor="lm")
    c.rect(56, yc+166, 430, 134, fill=CRIMBG, outline=CRIM, width=2.2, radius=14)
    c.text(80, yc+202, "Ranked attack path", bld(24), fill=CRIM, anchor="lm")
    c.text(80, yc+240, "exposure × exploitability × privilege × data-path", reg(18), fill=INK, anchor="lm")
    c.text(80, yc+270, "gated-multiplicative · MAX per jewel", reg(18), fill=INK, anchor="lm")
    c.text(462, yc+208, "87", bld(54), fill=CRIM, anchor="rm")
    ly=762
    c.line(80, ly, 156, ly, fill=CRIM, width=3.6); c.arrow(156, ly, 162, ly, fill=CRIM, width=3.6, head=15)
    c.text(176, ly, "Traversable edge (E_PATH) — walked as a hop", reg(20), fill=INK, anchor="lm")
    c.dline(700, ly, 782, ly, fill=SUBTLE, width=2.6); c.arrow(782, ly, 788, ly, fill=SUBTLE, width=2.6, head=13)
    c.text(802, ly, "Annotation — enriches a node, never a hop", reg(20), fill=INK, anchor="lm")
    return c.save("fig4_attackpath.png")

def d5_egress():
    c = Canvas(1460, 760)
    title_block(c, "Figure 5 — Egress Containment (zero-telemetry)",
                "Only three files may open a socket; enforced by a recursive-AST tripwire test")
    box(c, 560, 300, 340, 168, "OverWatch", ["engine + control plane","(pure, injected seams)"],
        fill=NAVY, border=NAVY, tf=bld(33), sf=reg(19), tcol=WHITE)
    allow=[("aws_kube.py","Kubernetes API (read-only)"),
           ("cnapp_connectors.py","Operator's OWN tools (Jira / Slack)"),
           ("aws_layer_fetch.py","Registry blobs (ECR + non-AWS OCI)")]
    for i,(f,p) in enumerate(allow):
        yy=180+i*126
        box(c, 1010, yy, 400, 100, f, p, fill=PANEL, border=ACCENT, tf=mon(22), sf=reg(17), tcol=NAVY)
        c.arrow(900, 384, 1010, yy+50, fill=ACCENT, width=2.8, head=13)
    c.text(1010, 566, "Each has a single documented purpose;", reg(17), fill=SUBTLE, anchor="lm")
    c.text(1010, 592, "re-checked on every redirect.", reg(17), fill=SUBTLE, anchor="lm")
    c.rect(56, 250, 448, 232, fill=GREENBG, outline=GREEN, width=2.2, radius=16)
    c.text(88, 292, "Customer's OWN AWS accounts", bld(25), fill=GREEN, anchor="lm")
    c.text(88, 332, "boto3 — read-only control-plane calls", reg(20), fill=INK, anchor="lm")
    c.text(88, 366, "the overwhelming majority of all egress;", reg(19), fill=SUBTLE, anchor="lm")
    c.text(88, 396, "never a data-plane / object read", reg(19), fill=SUBTLE, anchor="lm")
    c.text(88, 436, "assumed per-account, expires after the scan", reg(19), fill=SUBTLE, anchor="lm")
    c.arrow(560, 384, 504, 358, fill=GREEN, width=3.2, head=15)
    bx,by=560,560
    c.rect(bx, by, 340, 132, fill=CRIMBG, outline=CRIM, width=2.2, radius=16)
    c.text(bx+170, by+40, "Internet · telemetry · phone-home", sem(21), fill=CRIM, anchor="mm")
    c.text(bx+170, by+82, "BLOCKED", bld(29), fill=CRIM, anchor="mm")
    c.arrow(730, 468, 730, 560, fill=CRIM, width=2.8, dashed=True, head=15)
    c.d.ellipse([(710)*S,(496)*S,(750)*S,(536)*S], outline=CRIM, width=int(3.0*S))
    c.line(717, 503, 743, 529, fill=CRIM, width=3.0)
    c.text(56, 722, "Guard: tests/test_zero_telemetry.py — a recursive-AST scan of every shipped module fails CI if any other file holds a network primitive.",
           reg(18), fill=SUBTLE, anchor="lm")
    return c.save("fig5_egress.png")

if __name__ == "__main__":
    for fn in (d1_stack, d2_topology, d3_pipeline, d4_graph, d5_egress):
        name = fn()
        im = Image.open(os.path.join(OUT, name))
        print(f"{name:26s} {im.size[0]}x{im.size[1]}")
