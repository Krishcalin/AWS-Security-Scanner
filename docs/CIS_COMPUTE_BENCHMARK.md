# CIS AWS Compute Services Benchmark v2.0.0 — coverage

**All 82 recommendations, and what OverWatch does about each.** 33 were already covered by
checks that predate this mapping, 44 are covered by the 43 checks added for it, and 5
cannot be decided from the AWS control plane at all. Nothing is listed as covered without
naming the check that covers it.

> **On the source document.** CIS Benchmarks may not be redistributed, and the PDF is
> deliberately not in this repository. What is cited below is the recommendation *number*,
> which is a reference; every description is written from the underlying AWS behaviour
> rather than copied from the benchmark's own rationale, audit or remediation text.

## Why `CIS-COMPUTE` and not `CIS`

99 checks carry a `CIS` compliance key and every one of them is **CIS AWS
Foundations** numbering. The Compute benchmark re-uses the same section numbers for
entirely different controls — Foundations 2.1.2 is an Organizations authorization
guardrail, Compute 2.1.2 is "AMIs are encrypted" — so folding them into one key would silently
mis-cite every mapping in both directions. Compute controls therefore carry their own
`CIS-COMPUTE` key, a convention LMB-08 and LMB-09 already established.

## 2 — Amazon Elastic Compute Cloud (EC2)

| # | Control | OverWatch |
|---|---|---|
| 2.1.1 | AMI naming convention | **AMI-04** *(new)* — evaluates only when a convention is configured; see below |
| 2.1.2 | AMIs encrypted | AMI-02 |
| 2.1.3 | Only approved AMIs used | **AMI-05** *(new)* — running instances booted from an AMI owned by neither this account, Amazon, Marketplace, nor a trusted account |
| 2.1.4 | Images not older than 90 days | AMI-03 |
| 2.1.5 | Images not publicly available | AMI-01 |
| 2.2.1 | EBS encryption by default | EBS-01 |
| 2.2.2 | Public access to snapshots disabled | EBS-04 |
| 2.2.3 | Snapshots encrypted | EBS-03 |
| 2.2.4 | Unused volumes removed | EBS-05 |
| 2.2.5 | Attached volumes encrypted | EBS-02 |
| 2.3 | Tag policies enabled | **EC2-10** *(new)* |
| 2.4 | An organizational EC2 tag policy exists | **EC2-11** *(new)* |
| 2.5 | No instances older than 180 days | **EC2-12** *(new)* |
| 2.6 | Detailed monitoring on production instances | **EC2-13** *(new)* |
| 2.7 | Default security groups not in use | **EC2-14** *(new)* — VPC-04 asks whether the default group has rules; this asks whether anything is in it |
| 2.8 | IMDSv2 enforced | EC2-04 |
| 2.9 | Instances managed by Systems Manager | SSM-01 |
| 2.10 | Unused ENIs removed | **EC2-15** *(new)* |
| 2.11 | Instances stopped over 90 days removed | **EC2-16** *(new)* |
| 2.12 | Attached volumes deleted on termination | **EC2-17** *(new)* |
| 2.13 | No secrets in user data | EC2-07 |
| 2.14 | ASGs propagate tags at launch | **ASG-02** *(new)* |

## 3 — Amazon Elastic Container Service (ECS)

| # | Control | OverWatch |
|---|---|---|
| 3.1 | Host-mode task definitions not privileged or root | ECS-06 + ECS-01 + ECS-02 |
| 3.2 | `assignPublicIp` DISABLED for services | FARGATE-02 |
| 3.3 | `pidMode` not `host` | ECS-06 |
| 3.4 | `privileged` not `true` | ECS-01 |
| 3.5 | `readonlyRootFilesystem` true | ECS-05 |
| 3.6 | No secrets in container environment variables | ECS-04 |
| 3.7 | Logging configured | ECS-03 |
| 3.8 | Fargate services on a supported platform version | **ECS-09** *(new)* |
| 3.9 | Container Insights enabled | **ECS-10** *(new)* |
| 3.10 | Services tagged | **ECS-11** *(new)* |
| 3.11 | Clusters tagged | **ECS-12** *(new)* |
| 3.12 | Task definitions tagged | **ECS-13** *(new)* |
| 3.13 | Only trusted images | **ECS-14** *(new)* — the determinable half: the image is not in an ECR repository this estate controls |
| 3.14 | `assignPublicIp` DISABLED for task sets | **ECS-15** *(new)* |
| 3.15 | Task definitions use `awsvpc` | **ECS-16** *(new)* — ECS-06 keeps `host`, which is an escape primitive; this covers `bridge`/`none` |
| 3.16 | ECS Exec sessions logged | **ECS-17** *(new)* |

## 4 — Amazon EKS

Reference section; the benchmark carries no recommendations here. OverWatch's own EKS
coverage is EKS-01..08, KSPM-01..07 and KIEM-01..04.

## 5 — Amazon Lightsail

| # | Control | OverWatch |
|---|---|---|
| 5.1 | Applications inside instances updated | *not determinable — guest state* |
| 5.2 | Default application admin credentials changed | *not determinable — guest state* |
| 5.3 | SSH/RDP disabled when not needed | LSAIL-01 |
| 5.4 | SSH restricted by source | LSAIL-01 |
| 5.5 | RDP restricted by source | LSAIL-01 |
| 5.6 | IPv6 disabled when unused | **LSAIL-03** *(new)* |
| 5.7 | Bucket access managed through IAM | **LSAIL-04** *(new)* |
| 5.8 | Instances attached to buckets | **LSAIL-05** *(new)* |
| 5.9 | Buckets not publicly accessible | **LSAIL-06** *(new)* |
| 5.10 | Bucket access logging enabled | **LSAIL-07** *(new)* |
| 5.11 | Windows instances patched | *not determinable — guest state* |
| 5.12 | Auto-generated Windows password changed | *not determinable — see below* |

## 6 — 18: the remaining services

| # | Control | OverWatch |
|---|---|---|
| 6.1 | App Runner reaches source through a VPC | **APRUN-01** *(new)* |
| 7 | Auto Scaling | *no recommendations in the benchmark* |
| 8.1 | Batch jobs log to CloudWatch | **BATCH-01** *(new)* |
| 8.2 | Batch roles carry confused-deputy conditions | **BATCH-02** *(new)* |
| 9 | Compute Optimizer | *no recommendations* |
| 10.1 | Beanstalk managed platform updates | **EB-01** *(new)* |
| 10.2 | Beanstalk persistent logs | **EB-02** *(new)* |
| 10.3 | Beanstalk load-balancer access logs | **EB-03** *(new)* |
| 10.4 | Beanstalk HTTPS listener | **EB-04** *(new)* |
| 11.1 | CMK for Fargate ephemeral storage | **FARGATE-03** *(new)* |
| 12.1 | AWS Config enabled | LOG-03 |
| 12.2 | CloudWatch Lambda Insights | **LMB-10** *(new)* |
| 12.3 | Secrets Manager used for database credentials | LMB-03 |
| 12.4 | Least privilege on function access | **LMB-13** *(new)*, with IAM-\* and IAMPE-\* |
| 12.5 | One IAM role per function | **LMB-11** *(new)* |
| 12.6 | Functions not exposed to everyone | LMB-01 |
| 12.7 | Execution roles exist | **LMB-12** *(new)* |
| 12.8 | Code signing enabled | LMB-06 |
| 12.9 | No admin execution roles | **LMB-13** *(new)* |
| 12.10 | No unknown cross-account access | **LMB-14** *(new)* |
| 12.11 | Runtimes not end-of-support | LMB-04 |
| 12.12 | Environment variables on a CMK | **LMB-15** *(new)* |
| 12.13 | Layers not shared publicly | **LMB-16** *(new)* |
| 12.14 | Recursive-invocation detection on | **LMB-17** *(new)* |
| 12.15 | Function URLs without wildcard CORS | LMB-09 |
| 12.16 | Function URLs use IAM auth | LMB-08 |
| 12.17 | Functions in a customer-managed VPC | LMB-02 |
| 13-15 | Local Zones, Outposts, Serverless App Repository | *no recommendations* |
| 16.1 | SimSpace Weaver client encryption | *not determinable — see below* |
| 17.1 | Distribution configs do not publish AMIs | **IMGB-02** *(new)* |
| 17.2 | Pipelines do not bypass build cleanup | **IMGB-03** *(new)* |
| 18.1 | ECR image scanning | CNT-01 |
| 18.2 | ECR lifecycle policies | CNT-05 |
| 18.3 | ECR immutable tags | CNT-04 |
| 18.4 | Private ECR repos not publicly readable | CNT-03 |

## The five that are not implemented, and why

An exclusion without a reason is indistinguishable from an omission, so each is recorded
in `aws_cis_compute.NOT_DETERMINABLE` and asserted by `tests/test_cis_compute.py`:

- **5.1, 5.2, 5.11** — whether applications inside a Lightsail instance are patched, and
  whether their administrator credentials were changed, are properties of the guest. The
  Lightsail API reports the blueprint, not what is installed, and Lightsail instances are
  not SSM-managed, so there is no patch-compliance surface to read either.
- **5.12** — the auto-generated Windows password is retrievable only through
  `GetInstanceAccessDetails`, which returns a live credential. Reading one in order to
  audit it would breach the read-only-of-*config* charter, so this is declined on
  principle rather than on capability.
- **16.1** — the benchmark's own audit text states that SimSpace Weaver exposes no
  encryption setting. The control is a property of the customer's application protocol,
  not of any AWS resource, so no API read can decide it.

Adding registered-but-unfirable checks for these would inflate the published total and
lower the proportion of the catalogue that is proven to work — which is the exact defect
`docs/CHECK_FIRING.md` exists to make visible.

## AMI-04 needs configuring before it evaluates

"Consistent naming convention" is a statement about an organisation's policy, and no
property of an AMI reveals what that policy is. AMI-04 therefore reports `NOT EVALUATED`
until the convention is supplied, rather than guessing a pattern and failing correct
estates:

```bash
export OVERWATCH_AMI_NAME_PATTERN='^golden-[a-z]+-[0-9]{8}$'
```

or set `scanner.ami_name_pattern` directly. A non-matching owned AMI then FAILs at LOW.

## What this cost in permissions

23 read actions beyond what `SecurityAudit` already grants the shipped role — App Runner,
Batch, Beanstalk, the ECS cluster/service/task-set describes, the Image Builder
distribution and recipe reads, three Lambda reads, `lightsail:GetBuckets` and
`organizations:ListPolicies`. All are `Describe`/`Get`/`List`; `engine/aws_checkdef.py`
rejects any declaration naming a write verb at construction. Every one carries a written
justification in the permission ledger, and `tests/perm_ledger_baseline.py` pins the whole
surface so it cannot widen again without somebody deciding it should.
