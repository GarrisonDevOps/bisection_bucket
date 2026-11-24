---
title: 요청 시 LDAP 차단된 사용자 재동기화
tier: [ Free, Premium, Ultimate ]
offering: [ self_managed, gitlab_dedicated ]
stage: security_platform
co_create: true
documentation_link: "../../../administration/moderate_users/#resync-a-user-blocked-by-ldap"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255974
categories: [ System Access ]
level: secondary
weight: 10
---

관리자는 이제 관리 영역 **사용자** 페이지에서 단일 LDAP 차단된 사용자를 재동기화할 수 있습니다. 새로운 **LDAP와 재동기화** 작업은 LDAP 액세스 확인을 실행하고 LDAP이 액세스를 허용하면 사용자의 차단을 해제하거나, 허용하지 않으면 사용자를 차단된 상태로 유지합니다. 사용자에게 LDAP 신원이 없으면 작업이 메시지와 함께 거부됩니다. GitLab의 이전 버전에서는 LDAP 차단된 계정이 일일 사용자 동기화가 실행되거나 사용자가 로그인할 때까지 차단된 상태로 유지되었으며, 서비스 계정은 로그인할 수 없습니다.

이 기여를 해주신 [Sergey Pechenko](https://gitlab.com/tnt4brain)님께 감사드립니다([머지 리퀘스트](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255974))!
