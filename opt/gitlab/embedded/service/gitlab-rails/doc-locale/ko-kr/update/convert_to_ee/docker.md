---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Docker CE 인스턴스를 EE로 변환
---

기존 Docker용 GitLab Community Edition (CE) 컨테이너를 GitLab [Enterprise Edition](https://about.gitlab.com/pricing/) (EE) 컨테이너로 변환할 수 있습니다. [버전 업그레이드](../docker/_index.md)와 동일한 방식을 사용합니다.

CE를 EE의 동일한 버전으로 변환해야 합니다(예: CE 18.1에서 EE 18.1). 다만 필수는 아닙니다. 모든 표준 업그레이드(예: CE 18.0에서 EE 18.1)가 작동합니다. 다음 단계에서는 동일한 버전으로 변환한다고 가정합니다.

1. [백업](../../install/docker/backup.md)을 수행합니다. 최소한 [데이터베이스](../../install/docker/backup.md#create-a-database-backup)와 GitLab secrets 파일을 백업합니다.
1. 현재 CE 컨테이너를 중지하고 제거하거나 이름을 바꿉니다.
1. GitLab EE를 사용하는 새 컨테이너를 만들려면 `ce`을(를) `ee`(으)로 `docker run` 명령이나 `docker-compose.yml` 파일에서 바꿉니다. CE 컨테이너 이름, 포트 매핑, 파일 매핑 및 버전을 재사용합니다.
