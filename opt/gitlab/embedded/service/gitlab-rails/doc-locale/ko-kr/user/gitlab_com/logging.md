---
stage: none
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab.com 로그
description: GitLab.com이 로그를 생성하는 방법 및 작업 로그를 삭제하는 방법.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

GitLab.com의 로그에 대한 정보입니다.

## GitLab.com에서 로그를 생성하는 방법 {#how-gitlabcom-creates-logs}

[Fluentd](https://gitlab.com/gitlab-com/runbooks/tree/master/logging/doc#fluentd)는 GitLab 로그를 파싱한 후 다음으로 전송합니다:

- [Stackdriver Logging](https://gitlab.com/gitlab-com/runbooks/tree/master/logging/doc#stackdriver)는 로그를 Google Cloud Storage(GCS)에 장기적으로 저장합니다.
- [Cloud Pub/Sub](https://gitlab.com/gitlab-com/runbooks/tree/master/logging/doc#cloud-pubsub)는 [`pubsubbeat`](https://gitlab.com/gitlab-com/runbooks/tree/master/logging/doc#pubsubbeat-vms)을(를) 사용하여 로그를 [Elastic 클러스터](https://gitlab.com/gitlab-com/runbooks/tree/master/logging/doc#elastic)로 전달합니다.

자세한 내용은 다음 GitLab 런북을 참조하세요:

- [기록되는 항목의 상세 목록](https://gitlab.com/gitlab-com/runbooks/-/tree/master/docs/logging#what-are-we-logging)입니다.
- 현재 [로그 보존 정책](https://gitlab.com/gitlab-com/runbooks/-/tree/master/docs/logging#retention)입니다.
- [GitLab 로깅 인프라의 다이어그램](https://gitlab.com/gitlab-com/runbooks/-/tree/master/docs/logging#logging-infrastructure-overview)입니다.

## CI/CD 작업 로그 지우기 {#erase-cicd-job-logs}

기본적으로 GitLab은 CI/CD 작업 로그를 만료하지 않습니다. 작업 로그는 무기한 보존되며 GitLab.com에서 만료되도록 구성할 수 없습니다. 다음 방법 중 하나를 사용하여 작업 로그를 지울 수 있습니다:

- [Jobs API 사용](../../api/jobs.md#erase-a-job)합니다.
- 작업이 속한 [파이프라인 삭제](../../ci/pipelines/_index.md#delete-a-pipeline)합니다.
