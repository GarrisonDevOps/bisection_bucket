---
title: Control how Quick setup applies scan profiles
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/application_security/configuration/scanner_enablement_wizard/#quick-setup"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/23769
categories: [ Security Testing Configuration ]
weight: 50
---

You can now choose how the Scanner Enablement Wizard applies a [scan profile](../../../user/application_security/configuration/security_configuration_profiles.md) to a group. Previously, Quick setup attached the profile to every project, so projects already scanning through CI/CD configuration or a policy ran the scan twice.

Quick setup now asks how to apply it:

- **All projects**: Applies the profile to every project and replaces any existing profile for that scanner. Projects that scan another way run both scans.
- **Projects that don't scan yet** (recommended): Applies the profile to projects with no scan for that scanner. Projects that already scan keep their current setup.
- **Replace existing**: For projects that already have a profile for that scanner, replaces it with the new one.
