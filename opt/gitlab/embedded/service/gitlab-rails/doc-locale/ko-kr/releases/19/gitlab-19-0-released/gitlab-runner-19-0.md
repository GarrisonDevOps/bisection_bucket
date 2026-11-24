---
title: GitLab Runner 19.0
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: verify
documentation_link: "https://docs.gitlab.com/runner"
work_item: "https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/?milestone_title=19.0&state=closed"
categories: [ GitLab Runner Core ]
level: secondary
weight: 150
---

오늘 GitLab Runner 19.0도 함께 출시됩니다! GitLab Runner는 CI/CD 작업을 실행하고 결과를 GitLab 인스턴스로 보내는 높은 확장성의 빌드 에이전트입니다. GitLab Runner는 GitLab에 포함된 오픈 소스 지속적 통합 서비스인 GitLab CI/CD와 함께 작동합니다.

**새로운 기능**

- [러너 계측: 기능 협상, OTLP 내보내기 클라이언트 및 첫 `job_execution` 스팬](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39231)
- [러너 구성에 구성 가능한 준비 단계 타임아웃 추가](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/26583)

**버그 수정**

- [`FF_SCRIPTS_TO_STEPS` 기능 플래그 구현에 대한 포괄적인 수정](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39403)
- [S3 캐시 다운로드 시 `SignatureDoesNotMatch` 오류](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39402)
- [GitLab Runner가 S3 캐시를 사용하여 AWS에서 실행할 때 런타임 오류](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39386)
- [GitLab Runner 18.9.0 이상에서 `amd64`, `arm64`, `arm` 및 `armhf`에 대한 손상된 RPM S3 다운로드 링크](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39362)
- [음수 종료 코드가 Windows에서 잘못 보고됨](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39292)
- [부정확한 Kubernetes 실행기 서비스 컨테이너 명명 설명서](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39235)

모든 변경 사항 목록은 GitLab Runner [CHANGELOG](https://gitlab.com/gitlab-org/gitlab-runner/blob/19-0-stable/CHANGELOG.md)에 있습니다.
