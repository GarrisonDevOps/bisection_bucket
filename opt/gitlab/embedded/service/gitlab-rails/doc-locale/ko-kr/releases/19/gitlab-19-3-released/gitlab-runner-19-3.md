---
title: GitLab Runner 19.3
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: verify
documentation_link: https://docs.gitlab.com/runner
work_item: https://gitlab.com/gitlab-org/gitlab-runner/-/issues/?milestone_title=19.3&state=closed
categories: [ GitLab Runner Core ]
level: secondary
---

GitLab Runner 19.3을 오늘 릴리스합니다! GitLab Runner는 CI/CD 작업을 실행하고 결과를 GitLab 인스턴스로 보내는 높은 확장성의 빌드 에이전트입니다. GitLab Runner는 GitLab에 포함된 오픈 소스 지속적 통합 서비스인 GitLab CI/CD와 함께 작동합니다.

**새로운 기능**

- [작업 라우터 버전 호환성 매트릭스 문서화](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39408)
- [Workhorse가 작업 라우터를 위한 KAS에서 Rails 요청 경로에 있는지 확인](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39383)

**버그 수정**

- [`clear-docker-cache`은 `IMAGE_FILTER_FLAGS`이 비어 있을 때 사용하지 않는 모든 이미지를 정리합니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39621)
- [구체적 모드 디스패치는 `When`이 설정되지 않은 단계를 건너뜁니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39539)
- [`PrintPodWarningEvents`이 작동하지 않습니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/38982)
- [사용자 정의 실행기는 `.git` 폴더가 손상되었을 때 실패합니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/27540)

모든 변경 사항 목록은 GitLab Runner [CHANGELOG](https://gitlab.com/gitlab-org/gitlab-runner/blob/19-3-stable/CHANGELOG.md)에 있습니다.
