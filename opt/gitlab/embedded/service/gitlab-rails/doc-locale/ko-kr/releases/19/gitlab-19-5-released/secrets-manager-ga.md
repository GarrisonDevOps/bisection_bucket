---
title: GitLab Secrets Manager는 일반적으로 사용 가능합니다
tier: [ Premium, Ultimate ]
add_ons: ["GitLab Secrets Manager"]
offering: [ gitlab_com, self_managed ]
stage: software_supply_chain_security
documentation_link: "../../../ci/secrets/secrets_manager/"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/10723
categories: [ Secrets Management ]
level: primary
weight: 20
---

중앙 집중식 보안 정보 저장소가 없으면 자격 증명이 과도하게 제한된 CI/CD 변수, 로컬 구성 파일 및 독립 실행형 자격 증명 관리자 전체에 분산될 수 있습니다. 이로 인해 이들을 관리, 보호 및 감사하기가 더 어려워집니다.

GitLab Secrets Manager는 이제 GitLab.com 및 GitLab Self-Managed에서 일반적으로 사용 가능합니다. OpenBao를 기반으로 빌드되었으며, 기존 그룹 및 프로젝트 권한을 사용하므로 유지할 별도의 액세스 모델이 없습니다. 각 CI 보안 정보는 환경, 브랜치 및 브랜치 보호 규칙에 따라 필요한 작업의 범위로 지정됩니다. 감사 로그는 모든 생성, 읽기, 업데이트 및 삭제에 대해 생성됩니다.

GitLab Secrets Manager는 GitLab Credits를 소비합니다. [무료 30일 평가판 시작](../../../ci/secrets/secrets_manager/credit_usage.md#start-a-trial) 또는 [그룹 또는 인스턴스에 대해 활성화](../../../ci/secrets/secrets_manager/_index.md#enable-gitlab-secrets-manager)합니다.
