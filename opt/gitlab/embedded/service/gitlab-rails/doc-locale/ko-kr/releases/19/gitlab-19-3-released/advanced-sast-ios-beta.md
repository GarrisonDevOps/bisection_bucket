---
title: iOS용 Advanced SAST 베타
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: application_security_testin
documentation_link: "../../../user/application_security/sast/gitlab_advanced_sast"
work_item: "https://gitlab.com/groups/gitlab-org/-/work_items/22353"
categories: [ SAST ]
level: secondary
---

<!-- Category: SAST -->

GitLab Advanced SAST는 이제 Objective-C 및 Swift를 지원하며, 다른 언어를 위해 제공하는 것과 동일한 interprocedural taint 분석을 iOS 개발에 제공합니다. 베타는 GitLab 19.3부터 모든 GitLab Ultimate 고객을 위해 사용할 수 있습니다.

베타는 안전하지 않은 데이터 저장소, 손상된 암호화, 안전하지 않은 통신, 인증 및 권한 부여 결함을 포함한 주요 OWASP Mobile Top 10 취약성 클래스를 탐지합니다. 취약성이 한 언어로 시작하여 다른 언어의 싱크에 도달하면, Advanced SAST는 Swift와 Objective-C 언어 경계를 넘는 경로를 포함한 완전한 taint 경로를 탐지합니다.

활성화하려면 파이프라인에서 `GITLAB_ADVANCED_SAST_ENABLED: 'true'`을 설정합니다. 프로젝트에 Objective-C 또는 Swift 파일이 있으면 `gitlab-advanced-sast-ext` 작업이 자동으로 실행됩니다. 전체 설정 지침은 [Advanced SAST 설명서](../../../user/application_security/sast/gitlab_advanced_sast.md)를 참조하세요.

[베타 피드백 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/607091)에서 피드백을 공유하세요.
