---
title: 악성 패키지를 추가하는 머지 리퀘스트 차단
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/application_security/policies/merge_request_approval_policies/#block-malicious-packages-with-the-malware-rule"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/19465
categories: [ Security Policy Management ]
level: secondary
---

GitLab의 이전 버전에서는 머지 리퀘스트 승인 정책이 악성 패키지를 다른 취약성과 같이 처리했습니다. 발견이 해제되었거나 규칙의 심각도 필터 범위를 벗어난 경우, 해를 끼치기 위해 작성된 패키지도 여전히 병합될 수 있었습니다.

이제 머지 리퀘스트 승인 정책에 악성코드 규칙을 추가할 수 있습니다. 종속성 검사가 GitLab 악성코드 공지사항에 나열된 패키지를 감지하면, 발견의 심각도나 상태와 관계없이 머지 리퀘스트가 승인을 요구합니다. 악성코드 규칙은 기존 검사 발견 규칙과 함께 작동하므로, 정책을 다시 작성하지 않고 이미 보유한 정책에 이를 추가할 수 있습니다.

악성코드 규칙을 사용하려면 프로젝트가 [SBOM을 사용하여 종속성 검사](../../../user/application_security/dependency_scanning/dependency_scanning_sbom/_index.md#turn-on-dependency-scanning)를 실행해야 합니다. 악성코드 공지사항은 npm, PyPI, Maven, Go, NuGet, Cargo, RubyGems 패키지를 다룹니다.
