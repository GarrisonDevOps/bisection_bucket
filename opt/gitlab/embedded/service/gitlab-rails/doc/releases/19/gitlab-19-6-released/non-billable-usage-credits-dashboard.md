---
title: Non-billable usage across the GitLab Credits dashboard
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: fulfillment
documentation_link: "../../../subscriptions/gitlab_credits_dashboard/#non-billable-usage"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/633154
categories: [ Consumables Cost Management ]
level: secondary
---

The GitLab Credits dashboard summary cards and chart include non-billable usage, such as usage covered by a promotion.
Previously, the per-user and per-product breakdowns counted billable usage only, so they didn't add up to the totals.
The user list also skipped anyone with only non-billable usage.

GitLab now counts non-billable usage in:

- The **Usage by user** and **Usage by product** tabs.
- The user drill-down, where a badge on each non-billable event shows the reason.
- Your personal GitLab Credits usage page on GitLab.com.
