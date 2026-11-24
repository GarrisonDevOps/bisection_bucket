---
title: Automated triage and remediation profile (UI)
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/application_security/configuration/security_configuration_profiles/#automated-triage-and-remediation-profile"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/23192
categories: [ Vulnerability Management, Security Testing Configuration ]
weight: 50
---

You can now turn on security flows across a group the same way you turn on scanners. Apply an [automated triage and remediation profile](../../../user/application_security/configuration/security_configuration_profiles.md#automated-triage-and-remediation-profile) from the security inventory or the new **Automated Triage and Remediation** tab in Security configuration. The profile turns on the SAST, secret detection, and dependency scanning flows for the projects you select.

Previously, the profile was available only through the GraphQL API. Now you pick a preset and apply it in one action. For most flows:

- Conservative: on demand, high severity and above.
- Standard (recommended): automatic, medium severity and above.
- Proactive: automatic, every severity. Review credit use first.

The security inventory's new **Capabilities** column shows where flows run, next to where scans run.
