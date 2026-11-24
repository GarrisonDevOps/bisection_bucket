---
title: LDAP 그룹 동기화가 이제 감사자 역할을 관리할 수 있습니다
tier: [ Premium, Ultimate ]
offering: [ self_managed ]
stage: software_supply_chain_security
co_create: true
documentation_link: "../../../administration/auth/ldap/ldap_synchronization/#assign-an-auditor-role-to-an-ldap-group"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/247042
categories: [ System Access ]
level: secondary
---

이제 GitLab Self-Managed 인스턴스에 대해 LDAP 그룹 동기화를 사용하여 감사자 역할을 자동으로 부여하고 취소할 수 있습니다. 새로운 `audit_group` 설정은 LDAP 그룹을 감사자에게 매핑하며, 관리자를 위해 이미 수행한 `admin_group`과(와) 동일한 방식으로 작동하므로 감사자 액세스는 디렉터리 멤버십을 따르며 수동으로 유지되지 않습니다.

[Sergey Pechenko](https://gitlab.com/tnt4brain)의 기여에 감사합니다!
