---
title: Advanced SAST with Rust language support
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: application_security_testing
documentation_link: "../../../user/application_security/sast/advanced_sast_ext/"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/23728
categories: [ SAST ]
level: secondary
---

Previously, GitLab SAST had no coverage for Rust, so vulnerabilities in Rust code went
undetected by your pipeline.

GitLab Advanced SAST now scans Rust code. When you turn on GitLab Advanced SAST, Rust code in your
repository is analyzed automatically, with no additional configuration. Incremental scanning is
on by default, so only changed code is re-analyzed between pipelines.

Advanced SAST traces untrusted input across functions and files. Findings such as SQL injection,
command injection, and path traversal include a code flow from source to sink. For the weakness
types covered, see
[additional languages CWE coverage](../../../user/application_security/sast/advanced_sast_coverage.md#additional-languages-cwe-coverage).

Rust analysis was added in GitLab 19.5 and is in beta.
