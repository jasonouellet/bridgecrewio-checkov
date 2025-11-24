# Default Severities for IaC Checks

## Overview

This module provides default severity levels for Infrastructure as Code (IaC) checks when no Bridgecrew/Prisma Cloud API key is available.

## Motivation

Previously, IaC checks (Terraform, CloudFormation, Kubernetes, etc.) would only display severity information if:
1. A Bridgecrew/Prisma Cloud API key was provided
2. Metadata was successfully fetched from the platform

Without an API key, no severity information would be shown in scan outputs, making it difficult to prioritize findings.

## Solution

This module implements intelligent default severities based on check categories:

| Category | Default Severity | Rationale |
|----------|------------------|-----------|
| SECRETS | CRITICAL | Exposed secrets pose immediate security risks |
| IAM | HIGH | Identity and access misconfigurations can lead to privilege escalation |
| ENCRYPTION | HIGH | Data encryption is crucial for protecting sensitive information |
| APPLICATION_SECURITY | HIGH | Application vulnerabilities can be directly exploited |
| SUPPLY_CHAIN | HIGH | Supply chain attacks can compromise entire systems |
| API_SECURITY | HIGH | API vulnerabilities expose backend systems |
| SAST | HIGH | Code-level vulnerabilities need immediate attention |
| NETWORKING | MEDIUM | Network misconfigurations can expose services |
| GENERAL_SECURITY | MEDIUM | General best practices should be followed |
| KUBERNETES | MEDIUM | Container orchestration security is important |
| BACKUP_AND_RECOVERY | MEDIUM | Data protection and resilience |
| AI_AND_ML | MEDIUM | ML/AI specific security considerations |
| LOGGING | LOW | Logging issues are important but not critical |
| CONVENTION | LOW | Coding conventions and best practices |

## Usage

The default severities are automatically applied in two places:

1. **During pre_scan()**: The `PolicyMetadataIntegration` assigns default severities to all registered checks when no API metadata is available.

2. **During runtime**: Each framework runner (Terraform, CloudFormation, etc.) falls back to default severities when creating check records if `check.severity` is None.

## Important Notes

### These are defaults only
- Default severities are **approximations** based on general security best practices
- They may not reflect the actual risk level for your specific environment
- For accurate, up-to-date severities, **always use a Bridgecrew/Prisma Cloud API key**

### Severity assignment logic
When a check has multiple categories, the **highest severity** is assigned. For example:
- A check with categories `[LOGGING, IAM]` gets severity `HIGH` (from IAM)
- A check with categories `[CONVENTION, GENERAL_SECURITY]` gets severity `MEDIUM` (from GENERAL_SECURITY)

### Fallback behavior
If a check has no recognized categories, it defaults to `MEDIUM` severity.

## Testing

Run the unit tests to verify the default severity mappings:

```bash
python -m pytest tests/common/bridgecrew/test_default_severities.py -v
```

## Example Output

Without API key (before this change):
```
Check: CKV_AWS_23: "Ensure every security group and rule has a description"
        FAILED for resource: aws_security_group.test_sg
        File: /test.tf:8-18
```

Without API key (after this change):
```
Check: CKV_AWS_23: "Ensure every security group and rule has a description"
        FAILED for resource: aws_security_group.test_sg
        Severity: MEDIUM
        File: /test.tf:8-18
```

With API key (unchanged):
```
Check: CKV_AWS_23: "Ensure every security group and rule has a description"
        FAILED for resource: aws_security_group.test_sg
        Severity: LOW
        File: /test.tf:8-18
```

Note how the severity with an API key (LOW) may differ from the default (MEDIUM), demonstrating why API keys provide more accurate information.
