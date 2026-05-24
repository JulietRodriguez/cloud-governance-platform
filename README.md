# Cloud Governance Platform

## Overview

The Cloud Governance Platform is a cloud governance and DevSecOps portfolio project focused on secure Infrastructure-as-Code (IaC), automated compliance validation, and governance-oriented AWS resource management.

This project demonstrates how Terraform, GitHub Actions, and automated security scanning tools can be integrated to support secure cloud deployments and governance automation workflows.

---

# Project Objectives

- Deploy AWS infrastructure securely using Terraform
- Implement governance-focused cloud controls
- Automate infrastructure validation through CI/CD
- Integrate security scanning into deployment workflows
- Document security findings and remediation efforts
- Build a reusable governance automation framework

---

# Technologies Used

- Terraform
- AWS S3
- GitHub Actions
- tfsec
- Git
- VS Code
- AWS CLI

---

# Implemented Governance Controls

## S3 Security Controls

- Server-side encryption enabled
- Public access blocked
- Bucket versioning enabled
- Infrastructure tagging standards implemented

## DevSecOps Controls

- Automated Terraform validation
- CI/CD pipeline automation
- tfsec infrastructure security scanning
- Git-based change tracking

---

# CI/CD Pipeline

The GitHub Actions workflow automatically performs:

1. Terraform formatting validation
2. Terraform initialization
3. Terraform configuration validation
4. tfsec infrastructure security scanning

This pipeline supports continuous governance validation and infrastructure security assessment.

---

# Security Findings Management

Automated tfsec scanning identified governance recommendations including:

- KMS customer-managed encryption improvements
- S3 access logging recommendations

Findings and remediation tracking are documented within the project.

---

# Repository Structure

```text
cloud-governance-platform/
│
├── .github/workflows/
├── terraform/
├── evidence/
├── docs/
├── policies/
└── pipelines/
```

---

# Evidence Collection

The project includes deployment evidence and governance screenshots demonstrating:

- AWS infrastructure deployment
- Terraform execution
- Security control implementation
- GitHub Actions pipeline execution
- tfsec scanning results

---

# Future Enhancements

Planned improvements include:

- AWS CloudTrail integration
- IAM least privilege policies
- AWS Config governance rules
- Security Hub integration
- Policy-as-Code implementation
- Multi-environment Terraform deployment strategy

---

# Author

Juliet Rodriguez

Cloud Governance | DevSecOps | Infrastructure Security