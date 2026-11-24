---
title: GitLab 러너 19.5
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: verify
documentation_link: https://docs.gitlab.com/runner
work_item: https://gitlab.com/gitlab-org/gitlab-runner/-/issues/?milestone_title=19.5&state=closed
categories: [ GitLab Runner Core ]
level: secondary
---

오늘 GitLab 러너 19.5도 함께 릴리스합니다! GitLab Runner는 CI/CD 작업을 실행하고 결과를 GitLab 인스턴스로 보내는 높은 확장성의 빌드 에이전트입니다. GitLab Runner는 GitLab에 포함된 오픈 소스 지속적 통합 서비스인 GitLab CI/CD와 함께 작동합니다.

**새로운 기능**

- [도우미 컨테이너가 OOM으로 종료될 때 더 명확한 Kubernetes 실행기 오류 메시지](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39842)
- [작업 시작 시 작업 실행 환경의 CPU 모델 로깅](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39814)

**버그 수정**

- [Docker 서비스 상태 확인이 마지막으로 확인된 주소만 다이얼하기 때문에 IPv4 전용 서비스가 이중 스택 네트워크에서 실패](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39939)
- [인스턴스 접두사가 있는 러너 및 작업 토큰이 인식되지 않음](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39938)
- [Kubernetes 실행기가 모든 폴링에서 페이지가 매겨지지 않은 이벤트 `LIST` 요청을 전송하여 바쁜 클러스터에서 API 우선순위 및 공정성 포화](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39848)
- [Docker 실행기가 빌드 컨테이너만이 아닌 서비스 컨테이너에 `mac_address`를 적용](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39803)
- [`RUNNER_AFTER_SCRIPT_TIMEOUT`는 작업 시간 초과를 초과할 때 5분으로 재설정됨](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39717)
- [SigV4 서명된 헤더 규칙을 적용하는 S3 서버에서 `403`로 인해 캐시 업로드 실패. `cache_archiver`가 서명되지 않은 `Content-Type`를 전송하기 때문](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39701)
- [Kubernetes 실행기가 항상 빈 Pod 수준 `resources` 객체를 설정하여 Kubernetes 1.34 이상에서 `BestEffort` QoS 오분류 발생](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39671)
- [Step-runner 로컬 서버가 gRPC 서버가 수신하기 전에 준비 완료 보고](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39653)
- [문서화된 `systemd` 정상 종료 구성이 VirtualBox, Parallels 및 SSH 실행기의 실행 중인 VM 종료](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39563)
- [`proxy_exec`는 이미지에 다중 인수 `ENTRYPOINT`가 있을 때 작업을 실행하는 대신 도우미 바이너리 도움말을 출력하고 종료](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39452)
- [Docker 실행기는 같은 이미지의 여러 플랫폼을 가져올 때 `platform` 매개변수 무시](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/38514)

모든 변경 사항 목록은 GitLab Runner [CHANGELOG](https://gitlab.com/gitlab-org/gitlab-runner/blob/19-5-stable/CHANGELOG.md)에 있습니다.
