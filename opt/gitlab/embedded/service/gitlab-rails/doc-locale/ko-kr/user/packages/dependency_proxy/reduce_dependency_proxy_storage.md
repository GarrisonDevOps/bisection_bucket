---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 컨테이너 이미지에 대한 종속성 프록시 스토리지 감소
description: "정리 정책, API 캐시 지우기 및 TTL 설정을 통해 GitLab 종속성 프록시의 Blob 스토리지를 관리합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Blob에 대한 자동 제거 프로세스가 없습니다. 수동으로 삭제하지 않으면 무기한 저장됩니다. 이 페이지에서는 캐시에서 사용하지 않는 항목을 지우기 위한 여러 옵션을 다룹니다.

## 의존성 프록시 스토리지 사용 확인 {#check-dependency-proxy-storage-use}

[**사용 할당량**](../../storage_usage_quotas.md) 페이지에 컨테이너 이미지의 의존성 프록시 스토리지 사용을 표시합니다.

## API를 사용하여 캐시 지우기 {#use-the-api-to-clear-the-cache}

더 이상 필요하지 않은 이미지 blob이 사용하는 디스크 공간을 확보하려면 [의존성 프록시 API](../../../api/dependency_proxy.md)를 사용하여 전체 캐시를 지웁니다. 캐시를 지우면 다음에 파이프라인이 실행될 때 Docker Hub에서 이미지 또는 태그를 가져와야 합니다.

## 정리 정책 {#cleanup-policies}

{{< history >}}

- 필수 역할이 GitLab 15.0에서 Developer에서 Maintainer로 [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/350682)되었습니다.
- 필수 역할이 GitLab 17.0에서 Maintainer에서 Owner로 [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/370471)되었습니다.

{{< /history >}}

### GitLab 내에서 정리 정책 활성화 {#enable-cleanup-policies-from-within-gitlab}

사용자 인터페이스에서 컨테이너 이미지의 의존성 프록시에 대한 자동 TTL(Time-To-Live) 정책을 활성화할 수 있습니다. 이를 위해 그룹의 **설정** > **패키지 및 레지스트리** > **의존성 프록시**로 이동하여 90일 후 캐시에서 항목을 자동으로 지우도록 설정을 활성화합니다.

### GraphQL을 사용하여 정리 정책 활성화 {#enable-cleanup-policies-with-graphql}

정리 정책은 더 이상 사용하지 않는 캐시된 이미지를 지우고 추가 스토리지 공간을 확보하는 데 사용할 수 있는 예약된 작업입니다. 정책은 TTL(Time-To-Live) 논리를 사용합니다:

- 날짜 수가 구성됩니다.
- 해당 날짜 동안 가져오지 않은 모든 캐시된 의존성 프록시 파일이 삭제됩니다.

[GraphQL API](../../../api/graphql/reference/_index.md#mutationupdatedependencyproxyimagettlgrouppolicy)를 사용하여 정리 정책을 활성화하고 구성합니다:

```graphql
mutation {
  updateDependencyProxyImageTtlGroupPolicy(input:
    {
      groupPath: "<your-full-group-path>",
      enabled: true,
      ttl: 90
    }
  ) {
    dependencyProxyImageTtlPolicy {
      enabled
      ttl
    }
    errors
  }
}
```

[GraphQL 시작하기](../../../api/graphql/getting_started.md) 가이드를 참고하여 GraphQL 쿼리를 작성하는 방법을 배웁니다.

정책이 처음 활성화되면 기본 TTL 설정은 90일입니다. 활성화되면 오래된 의존성 프록시 파일이 매일 삭제 대기열에 추가됩니다. 처리 시간으로 인해 삭제가 즉시 발생하지 않을 수 있습니다. 캐시된 파일이 만료됨으로 표시된 후 이미지를 가져오면 만료된 파일은 무시되고 새 파일이 외부 레지스트리에서 다운로드되어 캐시됩니다.
