---
title: Track mean time to remediate in security dashboards
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/application_security/security_dashboard/#mttr-over-time"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/19830
categories: [ Vulnerability Management ]
level: secondary
---

In previous versions of GitLab, you couldn't see how quickly your teams fix vulnerabilities over time.

Project, group, and organization security dashboards now include a mean time to remediate (MTTR) chart.
It shows the weekly MTTR over the last 12 weeks, with the number of vulnerabilities remediated each week.
To find where remediation slows down, group the chart by severity or report type.
Compare the trend against your remediation SLAs.

MTTR counts recently detected vulnerabilities that were resolved or are no longer detected.
Dismissed vulnerabilities are excluded.
