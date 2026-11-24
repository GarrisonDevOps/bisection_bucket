---
title: GitLab Runner 19.4
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: verify
documentation_link: https://docs.gitlab.com/runner
work_item: https://gitlab.com/gitlab-org/gitlab-runner/-/issues/?milestone_title=19.4&state=closed
categories: [ GitLab Runner Core ]
level: secondary
---

오늘 GitLab Runner 19.4를 출시합니다! GitLab Runner는 CI/CD 작업을 실행하고 결과를 GitLab 인스턴스로 보내는 높은 확장성의 빌드 에이전트입니다. GitLab Runner는 GitLab에 포함된 오픈 소스 지속적 통합 서비스인 GitLab CI/CD와 함께 작동합니다.

**새로운 기능**

- [Fastzip이 캐시 및 아티팩트의 기본 압축기가 됩니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39681)
- [`runner`와 `system_id` 레이블을 `gitlab_runner_job_router_get_job_duration_seconds`에 추가합니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39576)
- [Job Router를 위한 전용 SLI, SLO 및 알림 통합을 추가합니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39533)
- [Kubernetes 실행기에 대한 일시 중단 및 재개 지원을 추가합니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39464)
- [작업 완료 `PUT` 요청에서 환경 키를 내보냅니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39463)
- [작업 로그에서 캐시 업로드 및 다운로드 URL을 억제하는 옵션](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39405)
- [Docker 실행기 구성에 `services_cap_add` 및 `services_cap_drop` 옵션을 추가합니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/4748)

**버그 수정**

- [Job router `409` 응답으로 인해 러너 관리자가 1시간 동안 비활성화됩니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39726)
- [logrotate 사용 작성기가 공유 러너 레이블을 변경하여 러너를 패닉 상태로 만들 수 있습니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39723)
- [Windows 서비스 콘솔 복원 실패로 인해 정상적으로 중지 중인 작업이 강제 종료됩니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39720)
- [히스토그램의 `job_id` 및 `runner_controller_id` 속성에 대한 무제한 카디널리티](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39719)
- [구성 유효성 검사에서 TOML 태그는 있지만 JSON 태그가 없는 null 가능 필드에 대해 `got null`를 경고합니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39688)
- [`get_sources`에서 Git 버전 확인으로 인한 SIGPIPE로 인한 간헐적 무음 실패](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39680)
- [`FF_USE_ADAPTIVE_REQUEST_CONCURRENCY`가 활성화되었을 때 `Request bottleneck` 경고가 표시됩니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39575)
- [AWS, GCP, Azure 및 GitLab Secrets Manager의 암호 해석 실패가 원인별로 분류됩니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39574)
- [러너 짧은 ID가 `-`로 시작할 때 Kubernetes 일시 중지 파드가 시작되지 않습니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39456)
- [Windows 서비스로 실행할 때 작업을 취소하면 항상 프로세스 종료가 발생합니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39297)

모든 변경 사항 목록은 GitLab Runner [CHANGELOG](https://gitlab.com/gitlab-org/gitlab-runner/blob/19-4-stable/CHANGELOG.md)에 있습니다.
