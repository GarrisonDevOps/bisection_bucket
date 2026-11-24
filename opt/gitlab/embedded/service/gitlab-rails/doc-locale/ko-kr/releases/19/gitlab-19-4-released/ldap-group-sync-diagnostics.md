---
title: LDAP 그룹 동기화 실패 진단
tier: [ Premium, Ultimate ]
offering: [ self_managed ]
stage: software_supply_chain_security
co_create: true
documentation_link: "../../../administration/auth/ldap/#ldap-sync-configuration-settings"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250622
categories: [ System Access ]
level: secondary
weight: 10
---

LDAP 그룹 동기화에 실패하면 이제 그 이유를 확인할 수 있습니다. 실패는 그룹에 대해 기록되고, 실패를 야기한 구성원이 표시되며(최대 5명), 그룹 구성원 페이지에 경고 알림이 표시되므로 이메일 도메인 제한으로 차단된 동기화를 UI에서 진단할 수 있습니다. 새로운 `group_filter` 설정을 통해 LDAP 항목 중 어느 것을 그룹으로 간주할지 좁힐 수 있습니다. 감사 로그는 이전에 하나의 항목을 공유했던 원인을 구분합니다: 생성 및 제거된 LDAP 그룹 링크와 LDAP 동기화로 차단된 사용자는 각각 이제 자신의 감사 이벤트 유형을 가집니다.

[Sergey Pechenko](https://gitlab.com/tnt4brain)의 이러한 기여에 감사합니다([MR 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250622) [MR 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/253816) [MR 3](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/252957) [MR 4](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/247146))!
