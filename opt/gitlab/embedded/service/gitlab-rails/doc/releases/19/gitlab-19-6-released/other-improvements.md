---
title: Other improvements
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: create
documentation_link: "../../../user/project/merge_requests/"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/262477
categories: [ Source Code Management ]
co_create: true
level: secondary
weight: 110
---

Community contributors made many improvements, including:

- The merge widget no longer briefly shows failed checks while a merge is in progress. ([Aleksandr Kotlyar](https://gitlab.com/aleksandr-kotlyar), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/266893))
- Footnotes cited more than once now all link correctly. ([José M. Requena Plens](https://gitlab.com/jmrp), [MR 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/265760) [MR 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/265411))
- The Starred tab on user profiles is now paginated. ([Radek Antoniuk](https://gitlab.com/rantoniuk), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/261375))
- Jobs with `needs:` dependencies now appear in the correct column in the pipeline dependency view. ([iDang3r](https://gitlab.com/iDang3r), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/262477))
- Group subproject and members lists now show the effective role. ([Gerardo Navarro](https://gitlab.com/gerardo-navarro), [MR 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256522) [MR 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256559))
- The Dependency Proxy now falls back to cached images during Docker Hub outages. ([Tri Lam](https://gitlab.com/trilamsr), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254559))
- Cached Dependency Proxy blobs are now served without requesting an upstream token. ([Thota Shashank](https://gitlab.com/thotashashank302), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/264118))
- Telegram notifications now HTML-escape project titles and branch names. ([kuttLoggin](https://gitlab.com/kuttLoggin), [MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/261103))
