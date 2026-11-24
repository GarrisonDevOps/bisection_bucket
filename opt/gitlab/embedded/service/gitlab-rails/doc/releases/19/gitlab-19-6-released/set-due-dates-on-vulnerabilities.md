---
title: Set vulnerability due dates on the details page
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/application_security/vulnerabilities/#set-a-due-date-for-a-vulnerability"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/638884
categories: [ Vulnerability Management ]
level: secondary
---

In previous versions of GitLab, you could set and view vulnerability due dates only
through the GraphQL API.

Now, you can view and set a vulnerability's due date from the vulnerability details page.
While the vulnerability has the **Needs triage** or **Confirmed** status, GitLab labels the date:

- **overdue**, after the date passes.
- **due soon**, when the date is in the next seven days.
