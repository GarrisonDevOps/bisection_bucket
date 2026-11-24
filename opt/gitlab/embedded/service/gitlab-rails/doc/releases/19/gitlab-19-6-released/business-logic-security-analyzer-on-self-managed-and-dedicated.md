---
title: Business Logic Security Analyzer on GitLab Self-Managed and GitLab Dedicated
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: application_security_testing
documentation_link: "../../../user/application_security/business_logic_scanning/"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/23435
categories: [ SAST ]
level: secondary
---

Business Logic Security Analyzer is a GitLab Duo Agent Platform flow that reasons about what
your code is meant to enforce. It finds vulnerabilities that pattern-based scanners miss:

- Broken object-level authorization.
- Missing authorization checks.
- Mass assignment.

Findings appear in the vulnerability report and the merge request security widget.

Until now, the Business Logic Security Analyzer was available only on GitLab.com.
Organizations on GitLab Self-Managed and GitLab Dedicated, which often have the strictest
requirements for where code is analyzed, couldn't use it.

Now it runs on both:

- On GitLab Dedicated, scans run on GitLab-hosted runners.
- On GitLab Self-Managed, scans run on your runners.
 
To get started, contact your account team.

Each scan consumes GitLab Credits. For setup, see
[Business logic scanning](../../../user/application_security/business_logic_scanning/_index.md).
