---
title: Review merge requests faster with Rapid Diffs
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_coding
documentation_link: "../../../user/project/merge_requests/changes/#rapid-diffs"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/19380
categories: [ Code Review Workflow ]
level: primary
---

In previous versions of GitLab, even small merge requests made you wait for the first diff to load.
Large ones could slow down or freeze the page.

Rapid Diffs, a ground-up rewrite of how GitLab renders diffs, is now generally available
and replaces the classic diff view.
GitLab renders diffs on the server and streams them to your browser, so reviews start in seconds:

- The first file appears in about 1.5 seconds, down from about 4.5 seconds.
- Browser search (<kbd>Control</kbd>+<kbd>F</kbd> or <kbd>Command</kbd>+<kbd>F</kbd>) works right away, without freezing the page.

Rapid Diffs also supports the review tools you already use:

- File-by-file mode
- Mark as viewed
- Full file view
- Commit-by-commit navigation
- Keyboard shortcuts
- Image comments
