# Repository Context Report: \[Repository Name\]

Generated on: \[ISO UTC Timestamp\]
Total Files Scanned: \[Count\]

## Tech Stack Summary

- **Languages**:
  - \[Language Name\] (Count: \[Number\])
- **Frameworks**:
  - \[Framework Name\] (e.g. Express, Django)
- **Databases**:
  - \[Database/Client Name\] (e.g. pg, mongoose, redis)
- **Identity/Auth**:
  - \[Auth Method\] (e.g. jsonwebtoken, keycloak)

## Infrastructure and Deployment

- **Cloud Provider**: \[AWS / GCP / Azure / Private Cloud\] (Detected via IaC files or assumed)
- **Containerization**: \[Docker / Kubernetes / Helm\]
- **CI/CD Pipelines**: \[GitHub Actions / GitLab CI / Jenkins\]

## Secrets Findings

- **Potential Credentials Exposure**:
  - **File**: \[relative path\]
  - **Line**: \[number\]
  - **Issue**: \[description of potential secret type\]
  - **Remediation**: \[steps to extract secret to secure config/vault\]

## Documented Assumptions

- *Assumption 1*: \[e.g. Production environment targets AWS EKS based on terraform definitions\]
- *Confidence Level*: \[High / Medium / Low\]
