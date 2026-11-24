---
title: 종속성 검사의 악성 패키지 탐지(베타)
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: application_security_testing
documentation_link: ../../../user/application_security/gitlab_advisory_database/
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/606037
categories: [ Software Composition Analysis ]
level: secondary
---

이전 버전의 GitLab에서는 종속성 검사가 알려진 CVE가 있는 패키지만 표시했습니다. 악성 패키지는 오타로 인한 혼동, 손상된 유지보수자 계정 또는 포함된 악성코드를 통해 해를 끼치도록 제작된 패키지로, 발견 사항을 생성하지 않았습니다.

GitLab 19.4는 베타 단계의 악성 패키지 탐지를 소개합니다. 종속성 검사는 이제 종속성을 [GitLab 악성코드 공지](../../../user/application_security/gitlab_advisory_database/_index.md#gitlab-malware-advisories)와 비교하여 확인하므로 위협이 널리 알려지기 전에 표시될 수 있습니다. 발견 사항은 종속성 목록 및 취약성 보고서에 빨간색 **악성코드** 배지와 함께 표시되며, 항상 중대 심각도이고 CVE가 아닌 `GLAM-` ID로 식별됩니다.

또한 머지 리퀘스트 승인 정책에서 [악성코드 규칙](../../../user/application_security/policies/merge_request_approval_policies.md#block-malicious-packages-with-the-malware-rule)을 사용하여 악성 패키지가 병합되기 전에 차단할 수 있습니다.

추가 설정이 필요하지 않습니다. 적용 범위는 [지원되는 패키지 유형](../../../user/application_security/gitlab_advisory_database/_index.md#supported-package-types): npm, PyPI, Maven, Go, NuGet, Cargo, RubyGems에 적용됩니다. 동일한 공지는 [지속적 취약성 검사](../../../user/application_security/continuous_vulnerability_scanning/_index.md#malicious-packages)를 제공하며, [오프라인 인스턴스](../../../topics/offline/quick_start_guide.md)는 이를 수동으로 다운로드합니다.

[이슈 606036](https://gitlab.com/gitlab-org/gitlab/-/work_items/606036)에 대한 피드백을 공유하세요.
