---
title: "Bun을 위한 종속성 검사 지원"
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: application_security_testing
documentation_link: "../../../user/application_security/dependency_scanning/dependency_scanning_sbom/#supported-languages-and-files"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/592701
categories: [ Software Composition Analysis ]
level: secondary
---

GitLab의 이전 버전에서 Bun JavaScript 런타임 및 패키지 관리자를 사용하는 프로젝트는 종속성 검사 지원을 받지 못했습니다.

이제 GitLab 종속성 검사는 `bun.lock` 파일을 구문 분석하여 Bun 프로젝트를 분석합니다(Bun 1.2에서 도입된 텍스트 기반 JSONC 형식).

Bun 패키지는 npm 레지스트리에서 소싱되므로, GitLab 권장사항 데이터베이스는 이미 이러한 종속성을 추가 구성 없이 포함합니다. npm, yarn 또는 pnpm의 대안으로 Bun을 사용하는 팀은 이제 표준 CI/CD 파이프라인의 일부로 알려진 취약성에 대해 프로젝트를 검사할 수 있습니다. 적격 결과는 종속성 검사 자동 수정도 지원합니다.
