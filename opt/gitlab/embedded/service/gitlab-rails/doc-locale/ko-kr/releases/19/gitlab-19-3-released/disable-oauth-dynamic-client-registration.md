---
title: MCP를 위한 OAuth Dynamic Client Registration 비활성화
tier: [ Free, Premium, Ultimate ]
offering: [ self_managed, gitlab_dedicated ]
stage: software_supply_chain_security
documentation_link: "../../../administration/settings/account_and_limit_settings/#oauth-dynamic-client-registration"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/601438
categories: [ System Access ]
level: secondary
weight: 50
---

이전에는 MCP 클라이언트와 AI 도구가 Dynamic Client Registration(DCR)을 통해 인스턴스에 OAuth 애플리케이션을 자동으로 등록할 수 있었으며, 이를 비활성화할 수 없었습니다. 이로 인해 GitLab Self-Managed 및 GitLab Dedicated 인스턴스의 관리자가 어떤 OAuth 클라이언트를 연결할 수 있는지 제어하기 어려웠습니다.

이제 애플리케이션 설정 API를 사용하여 DCR을 완전히 비활성화하여 인스턴스에 액세스할 수 있는 OAuth 클라이언트를 완전히 제어할 수 있습니다. DCR이 비활성화되면 클라이언트는 자동으로 등록하는 대신 사전에 등록된 OAuth 애플리케이션을 사용해야 합니다.
