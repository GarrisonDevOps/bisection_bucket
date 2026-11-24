---
stage: Verify
group: Pipeline Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Mock CI
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!note]
> 이 통합은 개발 환경에서만 사용할 수 있습니다.

모의 CI 서비스 서버를 설정하려면 다음 엔드포인트에 응답합니다:

- `commit_status`: `#{project.namespace.path}/#{project.path}/status/#{sha}.json`
  - 서비스가 `200 { status: ['failed'|'canceled'|'running'|'pending'|'success'|'success-with-warnings'|'skipped'|'not_found'] }`을(를) 반환하도록 합니다.
  - 서비스가 404를 반환하면, 서비스는 `pending`로 해석됩니다.
- `build_page`: `#{project.namespace.path}/#{project.path}/status/#{sha}`
  - 빌드가 연결된 위치입니다(구현 여부와 관계없이).

모의 CI 서버의 예를 보려면 [`gitlab-org/gitlab-mock-ci-service`](https://gitlab.com/gitlab-org/gitlab-mock-ci-service)을(를) 참조하세요.
