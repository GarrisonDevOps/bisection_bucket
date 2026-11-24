---
title: 해지된 GPG 신원이 더 이상 커밋을 검증하지 않음
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: create
co_create: true
documentation_link: "../../../user/project/repository/signed_commits/gpg/"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255300
categories: [ Source Code Management ]
level: secondary
weight: 70
---

GitLab은 이제 GPG에서 해지된 것으로 보고하는 사용자 ID를 무시합니다. 해지된 신원은 더 이상 사용자 설정의 **액세스** > **GPG 키** 아래에 나타나지 않으며 서명된 커밋의 **검증됨** 배지에 대해 검증된 이메일로 계산되지 않습니다. 해지된 신원으로 서명된 커밋은 "동일한 사용자, 다른 이메일" 또는 "다른 사용자"로 이동하고, 모든 신원이 해지된 키는 아무것도 검증하지 않습니다. 이미 확인된 키 아래에서 확인된 서명은 다시 유도되지 않습니다.

이 기여에 대해 [José M. Requena Plens](https://gitlab.com/jmrp) 님에게 감사합니다([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255300))!
