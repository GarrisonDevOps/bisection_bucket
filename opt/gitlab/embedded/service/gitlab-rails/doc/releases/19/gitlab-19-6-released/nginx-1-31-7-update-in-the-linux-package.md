---
title: NGINX updated to 1.31.7 in the Linux package
stage: gitlab_delivery
level: secondary
tier: [ Free, Premium, Ultimate ]
offering: [ self_managed ]
documentation_link: "../../../update/versions/gitlab_19_changes/#nginx-update-might-break-custom-nginx-configuration"
work_item: "https://gitlab.com/gitlab-org/omnibus-gitlab/-/work_items/10147"
categories: [ Omnibus Package ]
weight: 10
---

GitLab 19.6 updates the NGINX version bundled in the Linux package from 1.31.4 to 1.31.7.
This update fixes five security issues: CVE-2026-15176, CVE-2026-93479, CVE-2026-95101,
CVE-2026-97629, and CVE-2026-97205.

The configuration the Linux package generates is not affected. If you added custom NGINX
configuration, two upstream changes might break it:

- Zero-size buffer settings are now rejected.
- IP-address certificate verification now matches only IP subject alternative names.

Before you upgrade, review your custom configuration. For more information, see the
[upgrade notes](../../../update/versions/gitlab_19_changes.md#nginx-update-might-break-custom-nginx-configuration).
