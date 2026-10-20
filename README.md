# cloudaudit: AWS Cloud Security Configuration Auditor

A read-only scanner that checks an AWS account's **IAM, S3, EC2 and CloudTrail** settings against a subset of the
**CIS AWS Foundations Benchmark**. It produces a severity-ranked JSON/HTML report with a remediation step for each
finding. It also comes with a seeding harness that plants known misconfigurations and measures how many the scanner catches.

```
ingest (boto3 describe/get calls) -> check against rules -> findings with severity -> measure against answer key
```

## Results

### Real AWS sandbox (us-east-2, account inside an AWS-managed Organization)

| Metric | Value |
|---|---|
| Misconfigurations attempted | 22 |
| Refused by organization guardrails (SCPs) | 2: IAM console password (CIS 1.10), IAM groups (needed for 1.15 setup) |
| Planted (answer key) | **20** |
| Detected | **20 / 20 (100% recall)** |
| Unexpected findings | 3, all triaged below |
| Precision | 87% raw, **100% after triage** (every extra finding is a real issue) |
| Scan time | **10.0 s** for 21 checks, single region |
| Checks that errored | 1 (`IAM_USER_NO_MFA`: SCP denies `iam:GetLoginProfile`); the scan continued |

Triage of the unexpected findings:

| Finding | Verdict |
|---|---|
| `IAM_USER_DIRECT_POLICY` on `sandbox-admin` (AdministratorAccess) | True positive. Groups are blocked by an SCP, so the policy had to be attached directly. |
| `IAM_USER_DIRECT_POLICY` on `cloudaudit-scanner` (SecurityAudit) | True positive, same cause. |
| `IAM_ROOT_NO_MFA` (`AccountMFAEnabled = 0`) | True per the API. In an Organization-managed account the root user may have no credentials at all (centralised root access), so the real risk is low. Possible improvement: skip this finding when root has no password. |

What the real run showed:
- **Failure isolation matters.** One check was denied by an SCP. Because each check runs inside its own try/except, that check went into `errors` and the other 20 checks still ran.
- **Guardrails are a preventive control.** The organization blocked 2 of the 22 misconfigurations before they could exist. It also restricted the account to one region, which the seed script's preflight check now detects (`scripts/find_region.py`).

### moto (local, no AWS)

`python scripts/evaluate.py`: **24 / 24 detected, 0 false positives, ~0.3 s.** Moto allows planting things real AWS
won't, such as backdated access keys, buckets without encryption, and console users without MFA.

Caveat: the answer key and the checks were written together, so the moto score mostly shows that the plumbing works.
The real-account run and the unit-test edge cases are the stronger evidence: port ranges, `-1` all-traffic rules, IPv6,
UDP, conditional policies, service principals, inactive keys, non-default policy versions, buckets in other regions.

## Checks / CIS controls covered

| Check ID | Severity | CIS ref | What it flags |
|---|---|---|---|
| `IAM_ROOT_ACCESS_KEYS` | CRITICAL | 1.4 | Root user has access keys |
| `IAM_ROOT_NO_MFA` | CRITICAL | 1.5 | Root user has no MFA |
| `S3_PUBLIC_ACL` | CRITICAL | 2.1.4 | Bucket ACL grants `AllUsers` / `AuthenticatedUsers` |
| `S3_PUBLIC_POLICY` | CRITICAL | 2.1.4 | Bucket policy `Allow` to `Principal: *` with no condition |
| `CT_NOT_ENABLED` | HIGH | 3.1 | No multi-region trail that is currently logging |
| `EC2_OPEN_SSH` | HIGH | 5.2 / 5.3 | SG ingress to 22 from `0.0.0.0/0` or `::/0` (incl. ranges & all-traffic) |
| `EC2_OPEN_RDP` | HIGH | 5.2 / 5.3 | Same, port 3389 |
| `IAM_USER_NO_MFA` | HIGH | 1.10 | User with console password and no MFA device |
| `IAM_WILDCARD_ADMIN_POLICY` | HIGH | 1.16 | Customer-managed policy with `Allow` `Action:*` `Resource:*` |
| `S3_ACCOUNT_BPA_DISABLED` | HIGH | 2.1.4 | Account-level Block Public Access not fully on |
| `S3_BUCKET_BPA_DISABLED` | HIGH | 2.1.4 | Bucket-level Block Public Access not fully on |
| `CT_LOG_VALIDATION_DISABLED` | MEDIUM | 3.2 | Trail without log file validation |
| `EC2_DEFAULT_SG_IN_USE` | MEDIUM | 5.4 | Default security group attached to network interfaces |
| `EC2_EBS_DEFAULT_ENCRYPTION_OFF` | MEDIUM | 2.2.1 | EBS encryption-by-default disabled in region |
| `EC2_EBS_UNENCRYPTED` | MEDIUM | 2.2.1 | Unencrypted EBS volume |
| `IAM_STALE_ACCESS_KEY` | MEDIUM | 1.14 | Active access key older than 90 days |
| `IAM_WEAK_PASSWORD_POLICY` | MEDIUM | 1.8 / 1.9 | No policy, length < 14 or reuse prevention < 24 |
| `S3_NO_DEFAULT_ENCRYPTION` | MEDIUM | 2.1.1 (v1.4) | No default bucket encryption* |
| `S3_SSL_NOT_ENFORCED` | MEDIUM | 2.1.1 (v3.0) | Bucket policy doesn't deny `aws:SecureTransport=false` |
| `IAM_USER_DIRECT_POLICY` | LOW | 1.15 | User has attached/inline policies instead of group membership |
| `S3_NO_VERSIONING` | LOW | 2.1.3 | Versioning not enabled (or suspended) |

\* Since January 2023 AWS applies SSE-S3 to every bucket, so this check can only fire in moto or on very old setups.
CIS numbering changes between benchmark versions. Refs above follow v1.5/v3.0 unless noted.

`python -m cloudaudit list-checks` prints this list from the code.

## Design

```
cloudaudit/
  base.py        Severity (IntEnum), Finding (dataclass), AuditContext (session + client cache),
                 Check (base class, auto-registers subclasses), RegionalCheck (loops regions)
  checks/        s3.py  ec2.py  iam.py  cloudtrail.py  - one small subclass per control
  runner.py      runs every check, catches exceptions per check, sorts by severity, builds report
  report.py      JSON + self-contained HTML
  cli.py         `python -m cloudaudit scan ...`
scripts/
  seed.py        plants misconfigs (moto or real account) and writes answer_key.json
  evaluate.py    seeds+scans in moto, or scores a real report against a real answer key
  teardown.py    removes seeded resources and re-hardens account settings
  find_region.py finds regions the account may use (Organization SCPs often deny most)
  securityhub.py enables/compares/disables AWS Security Hub for a head-to-head benchmark
tests/           pytest + moto: positive and negative case for every check, runner, end-to-end
```

Adding a check is one class:

```python
class EbsDefaultEncryptionOff(RegionalCheck):
    id = "EC2_EBS_DEFAULT_ENCRYPTION_OFF"
    title = "EBS encryption by default is disabled"
    severity = Severity.MEDIUM
    cis_ref = "2.2.1"
    service = "ec2"
    remediation = "aws ec2 enable-ebs-encryption-by-default --region {region}"

    def run_region(self, ctx, region):
        if not ctx.client("ec2", region).get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
            yield self.finding(f"ebs-default-encryption/{region}", "New EBS volumes are not encrypted by default", region)
```

Other design choices:
- **Failure isolation.** `runner.run_checks` wraps each check (including lazy generator iteration). An `AccessDenied` or
  throttle in one check goes into `report["errors"]` and the rest of the scan continues.
- **Shared lookups.** The bucket list, security groups, IAM users and the account summary are fetched once per scan
  through `ctx.cache`. Clients use adaptive retries.
- **Per-region S3.** Each bucket is queried through a client in the bucket's own region.
- **Finding identity.** `(check_id, resource)` is the key used for scoring against the answer key.

## Quick start (no AWS account needed)

```bash
pip install -r requirements-dev.txt
pytest                         # 41 tests, ~10 s
python scripts/evaluate.py     # seed 24 misconfigs in moto, scan, score -> results/
```

`results/evaluation.json` holds the scores. `results/moto_report.{json,html}` is a sample report.

## Running against a real sandbox

> Use a **dedicated, empty** AWS account (or one you'll close). The seed step creates public buckets and
> internet-open security groups. Everything it creates is free-tier or free: it uses an ENI, not an instance, and a 1 GiB volume. Delete it afterwards anyway.

1. **Scanner identity (read-only).** Put the scanner in a group so it doesn't trigger CIS 1.15 itself:
   ```bash
   aws iam create-group --group-name auditors
   aws iam attach-group-policy --group-name auditors --policy-arn arn:aws:iam::aws:policy/SecurityAudit
   aws iam create-user --user-name cloudaudit-scanner
   aws iam add-user-to-group --group-name auditors --user-name cloudaudit-scanner
   aws iam create-access-key --user-name cloudaudit-scanner     # -> aws configure --profile scanner
   ```
2. **Plant misconfigurations** (with an *admin* profile, never the scanner):
   ```bash
   python scripts/seed.py --apply --profile sandbox-admin --region us-east-1   # writes answer_key.json
   ```
   Two items in the moto key can't be planted in real AWS: unencrypted buckets (S3 now always encrypts) and >90-day
   keys (key age can't be backdated). Root MFA is left out of the real key because your root user should have MFA.
   If you have a genuinely old key, add it to `answer_key.json` by hand.

   **Guardrails.** Accounts inside an AWS Organization (including AWS's newer "projects") may have
   service control policies that refuse some planting steps, e.g. creating IAM groups or console passwords.
   `seed.py` records each refused step under `"blocked"` in `answer_key.json` and leaves it out of the
   expected findings, so the score stays honest. The blocked list is worth reporting too: it shows which
   CIS controls the platform enforces preventively.
3. **Scan and time it**:
   ```bash
   time python -m cloudaudit scan --profile scanner --region us-east-1 -o report.json --html report.html
   ```
4. **Score**:
   ```bash
   python scripts/evaluate.py --answer-key answer_key.json --report report.json -o results/real_evaluation.json
   ```
   "Unexpected" findings in a real account aren't automatically false positives. They're often real
   pre-existing issues (e.g. no account password policy). Triage them and record which is which.
5. **Clean up**: `python scripts/teardown.py --profile sandbox-admin --suffix <suffix from answer_key.json>`

### Benchmark against AWS Security Hub

`scripts/securityhub.py` compares cloudaudit with Security Hub CSPM, AWS's managed checker for the same CIS
controls. It maps every cloudaudit check to the equivalent Security Hub control IDs (e.g. `EC2_OPEN_SSH` →
`EC2.13/EC2.53/EC2.54/EC2.19`) and matches findings by resource ARN.

```bash
python scripts/securityhub.py enable  --profile sandbox-admin --region us-east-2   # Config + Security Hub
python scripts/seed.py --apply        --profile sandbox-admin --region us-east-2
python -m cloudaudit scan             --profile scanner --region us-east-2 -o report.json
# wait: change-triggered controls ~30 min, periodic (IAM/root/password) up to 24 h
python scripts/securityhub.py compare --profile scanner --region us-east-2
python scripts/teardown.py            --profile sandbox-admin --region us-east-2 --suffix <suffix>
python scripts/securityhub.py disable --profile sandbox-admin --region us-east-2
```

The comparison reports detections for each planted misconfiguration, Security Hub's detection latency in
minutes, and the failed Security Hub controls cloudaudit has no check for (its coverage gaps).
Security Hub and Config are billed per check/item after the trial. A near-empty sandbox costs cents, but
run `disable` as soon as you have the numbers.

### CLI

```
python -m cloudaudit scan [--profile P] [--region R ...] [--service s3|ec2|iam|cloudtrail ...]
                          [--check CHECK_ID ...] [-o report.json] [--html report.html] [--fail-on HIGH]
python -m cloudaudit list-checks
```
`--fail-on SEVERITY` exits with code 2 if any finding is at or above that severity, so the scanner can gate a CI pipeline.

## Limitations / next steps

- Single-account. AWS Organizations / cross-account role assumption is not implemented.
- No CIS controls yet for CloudWatch metric filters (section 4), AWS Config, KMS rotation, VPC flow logs, or
  IAM Access Analyzer. Each is one more `Check` subclass.
- S3 public-access evaluation is static (ACL + policy parsing) and does not model every condition key. Real AWS
  also offers `GetBucketPolicyStatus` as a cross-check.
