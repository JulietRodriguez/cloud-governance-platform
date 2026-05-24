# Cloud Governance Risk Register

| Risk ID | Governance Risk | Impact | Implemented Control | Mitigation Strategy | Residual Risk | Governance Domain |
|---|---|---|---|---|---|---|
| R-001 | Public S3 bucket exposure | Unauthorized data access | S3 Public Access Block | Public access restrictions enforced through Terraform and AWS Config rules | Low | Security Governance |
| R-002 | Unencrypted storage resources | Data exposure risk | S3 Server-Side Encryption | AES256 encryption enabled through Terraform-managed controls | Low | Data Governance |
| R-003 | Unauthorized infrastructure changes | Governance drift and audit gaps | AWS CloudTrail | Continuous API activity logging and audit monitoring | Low | Audit Governance |
| R-004 | Excessive IAM permissions | Privilege escalation risk | Least Privilege IAM Policy | Scoped S3 permissions implemented using Terraform-managed IAM policies | Medium | Identity Governance |
| R-005 | Configuration drift | Noncompliant cloud resources | AWS Config Rules | Continuous compliance monitoring and governance evaluation | Low | Compliance Governance |
| R-006 | Insecure infrastructure deployment | Security misconfigurations | tfsec Security Scanning | Automated infrastructure security scanning integrated into CI/CD pipeline | Low | DevSecOps Governance |
| R-007 | Manual deployment inconsistencies | Operational governance gaps | Terraform Infrastructure-as-Code | Standardized and repeatable infrastructure deployment | Low | Infrastructure Governance |
| R-008 | Lack of governance visibility | Limited operational oversight | GitHub Actions CI/CD + AWS Monitoring | Automated validation, compliance checks, and governance monitoring workflows | Medium | Operational Governance |

# Governance Control Alignment

## AWS Native Governance Controls
- AWS CloudTrail
- AWS Config
- IAM Least Privilege Policies
- S3 Encryption Controls
- S3 Public Access Block

## DevSecOps Governance Controls
- GitHub Actions CI/CD
- tfsec Security Scanning
- Terraform Validation
- Infrastructure-as-Code Governance

## Governance Objectives Supported
- Compliance Monitoring
- Auditability
- Configuration Management
- Security Governance
- Identity Governance
- Continuous Compliance Enforcement
- Operational Governance Visibility