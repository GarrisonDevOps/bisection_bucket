---
title: Automatic false positive detection on tracked branches
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/application_security/vulnerabilities/false_positive_detection/#tracked-branches-and-tags"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/23511
categories: [ Vulnerability Management ]
level: secondary
---

In previous versions of GitLab, false positive detection ran automatically only on vulnerabilities
in the default branch. Findings on release branches and tags had to be triaged by hand.

Now, the SAST False Positive Detection Flow runs automatically on new Critical and High
vulnerabilities in any tracked branch, and in tracked tags that run SAST jobs, so you can filter out noise before you merge or ship.
It runs when you turn on false positive detection in your project settings, or when you use the
[automated triage and remediation profile](../../../user/application_security/configuration/security_configuration_profiles.md#automated-triage-and-remediation-profile) set to run automatically.

[Secret false positive detection](../../../user/application_security/vulnerabilities/secret_false_positive_detection.md#tracked-branches-and-tags)
on tracked branches and tags is available on GitLab.com in this release.
