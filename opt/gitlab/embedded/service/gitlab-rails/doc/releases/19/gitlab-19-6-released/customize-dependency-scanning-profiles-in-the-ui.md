---
title: Customize dependency scanning profiles in the UI
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/application_security/configuration/security_configuration_profiles/"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/20200
categories: [ Security Testing Configuration ]
weight: 50
---

You can now create and customize dependency scanning profiles in the UI, the same way as secret detection and SAST profiles. Set how dependency scanning runs once for a group, then apply it to every project without editing `.gitlab-ci.yml` in each one.

Previously, you could customize a dependency scanning profile only with the GraphQL API. Now go to **Secure** > **Security configuration**, select the **Scanners** tab, and select **Manage profiles** on the dependency scanning row. Choose whether scans run on merge request pipelines, default branch pipelines, or both, then add settings to override, such as paths to exclude.

Apply the profile [from the security inventory](../../../user/application_security/configuration/security_configuration_profiles.md#apply-profiles-in-the-ui) or in the [advanced setup of the Scanner Enablement Wizard](../../../user/application_security/configuration/scanner_enablement_wizard.md#advanced-setup).
