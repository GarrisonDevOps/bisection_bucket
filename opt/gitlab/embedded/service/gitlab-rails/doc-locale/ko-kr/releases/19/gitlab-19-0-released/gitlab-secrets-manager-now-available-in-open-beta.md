---
title: GitLab Secrets Manager 이제 공개 베타에서 사용 가능
stage: software_supply_chain_security
level: primary
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed ]
documentation_link: "../../../ci/secrets/secrets_manager/"
work_item: "https://gitlab.com/groups/gitlab-org/-/work_items/21731"
categories: [ Secrets Management ]
weight: 30
---

이전 버전의 GitLab에서는 GitLab Secrets Manager가 비공개 베타 사용자 그룹에만 제공되었습니다. 대부분의 팀은 HashiCorp Vault 또는 AWS Secrets Manager와 같은 외부 서비스에 의존했습니다.

GitLab Secrets Manager는 이제 GitLab.com 및 GitLab Self-Managed의 Premium 및 Ultimate 고객을 위해 공개 베타로 제공됩니다. GitLab Secrets Manager가 활성화되면 프로젝트 및 그룹 소유자는 GitLab에서 CI/CD 시크릿을 저장, 검색 및 참조할 수 있습니다. 시크릿은 프로젝트 또는 그룹으로 범위가 지정되며 명시적으로 요청하는 파이프라인 작업에만 액세스할 수 있습니다.

공개 베타 동안 GitLab Secrets Manager는 [베타 지원 정책](../../../policy/development_stages_support.md#beta)을 따르며 프로덕션 사용 준비가 되지 않았을 수 있습니다.

피드백을 공유하려면 [이슈 598100](https://gitlab.com/gitlab-org/gitlab/-/issues/598100)을 참조하세요.
