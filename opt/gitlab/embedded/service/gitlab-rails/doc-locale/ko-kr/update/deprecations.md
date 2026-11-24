---
stage: none
group: none
info: "To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>"
toc: false
title: 버전별 기능 중단 및 제거
---

다음 GitLab 기능은 더 이상 사용을 권장하지 않습니다.

- 각 중단된 기능은 향후 릴리스에서 제거됩니다.
- 일부 기능은 제거될 때 호환성을 깨는 변경을 일으킵니다.
- GitLab.com에서는 릴리스 이전 달 동안 언제든지 중단된 기능을 제거할 수 있습니다.
- 제거된 기능에 대한 설명서를 보려면 [GitLab Docs 아카이브](https://docs.gitlab.com/archives/)를 참조하세요.
- GraphQL API 중단에 대해 [중단된 항목 없이 API 호출이 작동하는지 확인](../api/graphql/_index.md#verify-against-the-future-breaking-change-schema)해야 합니다.

이 기능 중단 정보를 고급 검색 및 필터링하려면 [저희 Customer Success 팀에서 만든 도구](https://gitlab-com.gitlab.io/cs-tools/gitlab-cs-tools/what-is-new-since/?tab=deprecations)를 시도해보세요.

[REST API 중단](../api/rest/deprecations.md)은 별도로 문서화됩니다.

{{< icon name="rss" >}} **예정된 호환성 깨는 변경 사항에 대한 알림을 받으려면**, 이 URL을 RSS 피드 리더에 추가하세요: `https://docs.gitlab.com/releases/breaking-changes.xml`

<!-- vale off -->
<!--
DO NOT EDIT THIS PAGE DIRECTLY

This page is automatically generated from the template located at
`data/deprecations/templates/_deprecation_template.md.erb`, using
the YAML files in `/data/deprecations` by the Rake task
located at `lib/tasks/gitlab/docs/compile_deprecations.rake`,

For deprecation authors (usually Product Managers and Engineering Managers):

- To add a deprecation, use the example.yml file in `/data/deprecations/templates` as a template.
- For more information about authoring deprecations, check the deprecation item guidance:
  <https://handbook.gitlab.com/handbook/marketing/blog/release-posts/#update-the-deprecations-doc>

For deprecation reviewers (Technical Writers only):

- To update the deprecation doc, run: `bin/rake gitlab:docs:compile_deprecations`
- To verify the deprecations doc is up to date, run: `bin/rake gitlab:docs:check_deprecations`
- For more information about updating the deprecation doc, see the deprecation doc update guidance:
  <https://handbook.gitlab.com/handbook/marketing/blog/release-posts/#update-the-deprecations-doc>
-->

## GitLab 21.0 {#gitlab-210}

### Code Suggestions v2 및 v3 AI Gateway 엔드포인트 {#code-suggestions-v2-and-v3-ai-gateway-endpoints}

- GitLab 19.5에서 발표됨
- GitLab 21.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/605661)를 참조하세요.

AI Gateway 엔드포인트 `/v2/completions`, `/v2/code/completions`, `/v2/code/generations`, 및 `/v3/code/completions`는 GitLab 19.5에서 중단되었으며 GitLab 21.0에서 제거될 예정입니다. Code Suggestions 요청은 대신 `/v4/code/suggestions`을 사용해야 합니다.

GitLab.com은 GitLab 19.1부터 `/v4/code/suggestions`을 사용했습니다. GitLab.com의 경우 조치가 필요하지 않습니다.

GitLab Self-Managed, GitLab Dedicated, 및 GitLab 편집기 확장 프로그램은 향후 릴리스에서 v4 엔드포인트로 전환됩니다. 이 변경 사항이 포함된 버전을 추적하려면 [이슈 605661](https://gitlab.com/gitlab-org/gitlab/-/issues/605661)을 참조하세요. 자체 호스팅 AI Gateway를 실행하는 경우, GitLab 21.0용 AI Gateway 이미지도 이러한 엔드포인트를 제거합니다.

중단을 피하려면 GitLab 21.0이 릴리스되기 전에:

- 인스턴스를 최신 버전의 GitLab으로 업그레이드합니다.
- 편집기 확장 프로그램을 최신 버전으로 업데이트합니다.
- AI Gateway를 직접 호출하는 사용자 정의 클라이언트를 `/v4/code/suggestions`을 사용하도록 업데이트합니다.

## GitLab 20.0 {#gitlab-200}

### 규정 준수 파이프라인 {#compliance-pipelines}

- GitLab 17.3에서 발표됨
- GitLab 20.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/groups/gitlab-org/-/epics/11275)를 참조하세요.

현재 규정 준수 또는 보안 관련 작업이 프로젝트 파이프라인에서 실행되도록 보장하는 두 가지 방법이 있습니다:

- [규정 준수 파이프라인](https://docs.gitlab.com/user/compliance/compliance_pipelines/).
- [보안 정책](https://docs.gitlab.com/user/application_security/policies/).

프로젝트에 대한 모든 파이프라인에서 필수 작업이 실행되도록 하기 위한 단일 위치를 제공하기 위해 GitLab 17.3에서 규정 준수 파이프라인을 중단했으며 GitLab 20.0에서 이 기능을 제거할 예정입니다.

고객은 규정 준수 파이프라인에서 새로운 [파이프라인 실행 정책 유형](https://docs.gitlab.com/user/application_security/policies/pipeline_execution_policies/)으로 가능한 한 빨리 마이그레이션해야 합니다.

자세한 내용은 다음을 참조하세요:

- [마이그레이션 가이드](https://docs.gitlab.com/user/compliance/compliance_pipelines/#pipeline-execution-policies-migration).
- [블로그 게시물](https://about.gitlab.com/blog/why-gitlab-is-deprecating-compliance-pipelines-in-favor-of-security-policies/).

### 패키지용 Dependency Proxy는 중단됨 {#dependency-proxy-for-packages-is-deprecated}

- GitLab 19.1에서 발표됨
- GitLab 20.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/601255)를 참조하세요.

패키지용 Dependency Proxy는 중단되었으며 향후 릴리스에서 제거될 예정입니다. 이 기능은 **Maven 가상 레지스트리**로 대체되었으며, 이는 향상된 성능, 더 나은 업스트림 프록시 및 캐싱 기능, 그리고 GitLab의 패키지 관리 워크플로우와 더 깊은 통합을 제공합니다.

**조치 필요:** 패키지 관리자 구성을 Dependency Proxy for packages 엔드포인트에서 Maven 가상 레지스트리로 마이그레이션합니다. 설정 지침은 [Maven 가상 레지스트리 설명서](https://docs.gitlab.com/user/packages/virtual_registry/maven/)를 참조하세요.

### GraphQL에서 `previousStageJobs` 제거 {#deprecate-previousstagejobs-from-graphql}

- GitLab 19.2에서 발표됨
- GitLab 20.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/603950)를 참조하세요.

GraphQL `CiJob` 유형의 `previousStageJobs` 필드는 중단되었으며 GitLab 20.0에서 제거될 예정입니다. GitLab UI가 더 이상 종속성을 계산하기 위해 `previousStageJobs`을 필요로 하지 않으므로 서버 측 대체 항목이 필요하지 않습니다.

### Design Management 중단 {#design-management-deprecated}

- GitLab 18.6에서 발표됨
- GitLab 20.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/groups/gitlab-org/-/work_items/20375)를 참조하세요.

GitLab 20.0에서 GitLab은 Design Management 기능 중단을 시작합니다. Design Management를 통해 사용자는 와이어프레임 및 목업과 같은 디자인 자산을 GitLab 이슈에 업로드하여 협업할 수 있습니다. 기존 사용량 및 예상 고객 영향을 신중히 검토한 후 이 결정을 내렸습니다. Design Management에 필요한 지속적인 유지보수가 현재 사용량을 초과했으며, 최신 디자인 워크플로우와 더 잘 맞는 솔루션에 노력을 집중하고 있습니다. GitLab 20.0 이상에서는 사용자가 더 이상 새 디자인을 업로드할 수 없습니다. 기존 디자인은 GitLab 21.0까지 읽기 전용 모드로 유지되어 사용자가 필요에 따라 디자인을 저장할 시간을 제공합니다. GitLab은 디자이너가 이미 사용하는 도구와 더 잘 통합되는 대체 솔루션을 모색하고 있습니다.

### 감사 이벤트 API에 키셋 페이지 매김 적용 {#enforce-keyset-pagination-on-audit-event-api}

- GitLab 17.8에서 발표됨
- GitLab 20.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/382338)를 참조하세요.

인스턴스, 그룹 및 프로젝트용 감사 이벤트 API는 현재 선택적 키셋 페이지 매김을 지원합니다. GitLab 20.0에서는 이러한 API에 키셋 페이지 매김을 강제합니다.

### GitLab Helm 차트 값 `gitlab.kas.ingress.grpc.enabled` {#gitlab-helm-chart-value-gitlabkasingressgrpcenabled}

- GitLab 19.5에서 발표됨
- GitLab 20.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/charts/gitlab/-/work_items/6663)를 참조하세요.

GitLab Helm 차트에서 KAS gRPC Ingress는 이제 `global.kas.ingress.grpc.enabled`으로 제어되며, 이는 Kubernetes 에이전트에 알려진 주소가 기본 gRPC (`grpcs://`)를 사용하는지 아니면 WebSocket (`wss://`)을 사용하는지도 결정합니다.

`kas` 차트의 로컬 값 `gitlab.kas.ingress.grpc.enabled`는 중단되었으며 차트 11.0 (GitLab 20.0)에서 제거될 예정입니다. 여전히 gRPC Ingress가 렌더링되는지 여부를 제어하지만 다른 차트는 알려진 주소를 파생할 때 이를 볼 수 없으므로 Ingress와 주소가 불일치할 수 있습니다.

`gitlab.kas.ingress.grpc.enabled`을 설정한 경우, 차트 11.0으로 업그레이드하기 전에 값을 `global.kas.ingress.grpc.enabled`로 이동합니다. 둘 다 설정하지 않으면 기본값이 유지됩니다. gRPC Ingress는 NGINX Ingress 공급자에 대해 렌더링되며, 차트가 gRPC를 KAS로 라우팅할 때 에이전트는 `grpcs://`을 가리킵니다.

### Go 모듈 프록시 (실험적) 중단됨 {#go-module-proxy-experimental-is-deprecated}

- GitLab 19.1에서 발표됨
- GitLab 20.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/592132)를 참조하세요.

GitLab 패키지 레지스트리의 실험적 Go 모듈 프록시는 중단되었으며 GitLab 20.0에서 제거될 예정입니다. 이 기능은 실험적 상태를 벗어나지 못했습니다.

이 기능은 **Go 가상 레지스트리**로 대체될 예정이며, 이는 GitLab을 통해 Go 모듈을 해석하기 위한 더욱 완전하고 안정적인 경험을 제공합니다.

**조치 필요:** GitLab을 Go 모듈 프록시로 사용 중인 경우, Go 가상 레지스트리가 사용 가능해지면 마이그레이션할 계획을 세우세요. 그 사이에 `proxy.golang.org` 또는 자체 호스팅 솔루션과 같은 대체 프록시를 구성하고 `GOPROXY` 환경 변수를 업데이트할 수 있습니다.

### GraphQL `useWorkItemsView` 사용자 기본 설정 {#graphql-useworkitemsview-user-preference}

- GitLab 19.5에서 발표됨
- GitLab 20.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/550770)를 참조하세요.

`UserPreferences` 유형의 `useWorkItemsView` 필드 및 `userPreferencesUpdate` 뮤테이션의 `useWorkItemsView` 인수는 GitLab 19.5에서 중단되었으며 GitLab 20.0에서 제거될 예정입니다. 이슈에서 작업 항목으로의 마이그레이션이 완료되었으며 작업 항목 보기가 항상 사용되므로 이 기본 설정은 불필요합니다. GitLab 19.5부터 인수는 허용되지만 무시되며 필드는 항상 `true`을 반환합니다. 뮤테이션에서 인수를 제거하고 쿼리에서 필드를 제거하세요. 대체 항목이 없습니다.

### 레거시 `retry:when` 실패 이유 `stuck_or_timeout_failure` 및 `job_execution_timeout` 중단 {#legacy-retrywhen-failure-reasons-stuck_or_timeout_failure-and-job_execution_timeout-are-deprecated}

- GitLab 19.1에서 발표됨
- GitLab 20.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/602133)를 참조하세요.

GitLab 19.0에서 일반적인 `stuck_or_timeout_failure` 및 `job_execution_timeout` 작업 실패 이유가 더 구체적인 이유 집합으로 분할되었습니다 (예: `stuck_pending_no_matching_runners`, `no_updates_running`, 및 `server_timeout_running`). 새 빌드는 더 이상 이전 이유로 기록되지 않습니다.

이러한 이전 이유는 `.gitlab-ci.yml`의 [`retry:when`](https://docs.gitlab.com/ci/yaml/#retrywhen)에 대한 유효한 값으로 유지됩니다. 기존 구성을 자동으로 깨는 것을 피하기 위해 `retry:when` 아래에 `stuck_or_timeout_failure` 또는 `job_execution_timeout`를 나열할 때 GitLab은 이들을 대체 항목으로 취급하여 이들을 대체한 특정 이유의 전체 집합과 일치합니다. 또한 GitLab은 CI lint 출력 및 파이프라인 편집기에서 이러한 값을 사용할 때 차단하지 않는 경고를 표시합니다.

두 값 모두 중단되었으며 GitLab 20.0에서 제거 예정입니다.

**조치 필요:** `retry:when`을 업데이트하여 특정 실패 이유를 사용하도록 합니다:

- `stuck_or_timeout_failure`을 `stuck_pending_with_matching_runners`, `stuck_pending_no_matching_runners`, `no_updates_running`, 및 `no_updates_canceling`의 관련 부분 집합으로 바꿉니다.
- `job_execution_timeout`을 `server_timeout_running` 및/또는 `server_timeout_canceling`으로 바꿉니다.

### 레거시 그룹 수준 감사 이벤트 스트리밍 대상 GraphQL API {#legacy-group-level-audit-event-streaming-destination-graphql-apis}

- GitLab 18.10에서 발표됨
- GitLab 20.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/groups/gitlab-org/-/work_items/12339)를 참조하세요.

다음 그룹 수준 GraphQL 감사 이벤트 스트리밍 대상 API는 중단되었으며 GitLab 20.0에서 제거될 예정입니다.

중단된 뮤테이션:

- `externalAuditEventDestinationCreate` - 대신 `groupAuditEventStreamingDestinationsCreate`를 사용합니다.
- `externalAuditEventDestinationDestroy` - 대신 `groupAuditEventStreamingDestinationsDelete`를 사용합니다.
- `externalAuditEventDestinationUpdate` - 대신 `groupAuditEventStreamingDestinationsUpdate`를 사용합니다.
- `googleCloudLoggingConfigurationCreate` - 대신 `gcpLogging` 카테고리와 함께 `groupAuditEventStreamingDestinationsCreate`를 사용합니다.
- `googleCloudLoggingConfigurationDestroy` - 대신 `groupAuditEventStreamingDestinationsDelete`를 사용합니다.
- `googleCloudLoggingConfigurationUpdate` - 대신 `groupAuditEventStreamingDestinationsUpdate`를 사용합니다.
- `auditEventsAmazonS3ConfigurationCreate` - 대신 `amazonS3` 카테고리와 함께 `groupAuditEventStreamingDestinationsCreate`를 사용합니다.
- `auditEventsAmazonS3ConfigurationDelete` - 대신 `groupAuditEventStreamingDestinationsDelete`를 사용합니다.
- `auditEventsAmazonS3ConfigurationUpdate` - 대신 `groupAuditEventStreamingDestinationsUpdate`를 사용합니다.
- `auditEventsStreamingHeadersCreate` - `groupAuditEventStreamingDestinationsUpdate`를 사용하여 스트리밍 대상 구성으로 헤더를 구성합니다.
- `auditEventsStreamingHeadersDestroy` - `groupAuditEventStreamingDestinationsUpdate`를 사용하여 스트리밍 대상 구성으로 헤더를 구성합니다.
- `auditEventsStreamingHeadersUpdate` - `groupAuditEventStreamingDestinationsUpdate`를 사용하여 스트리밍 대상 구성으로 헤더를 구성합니다.
- `auditEventsStreamingDestinationEventsAdd` - 대신 `auditEventsGroupDestinationEventsAdd`를 사용합니다.
- `auditEventsStreamingDestinationEventsRemove` - 대신 `auditEventsGroupDestinationEventsRemove`를 사용합니다.
- `auditEventsStreamingHttpNamespaceFiltersAdd` - 대신 `auditEventsGroupDestinationNamespaceFilterCreate`를 사용합니다.
- `auditEventsStreamingHttpNamespaceFiltersDelete` - 대신 `auditEventsGroupDestinationNamespaceFilterDelete`를 사용합니다.

중단된 그룹 필드:

- `Group.externalAuditEventDestinations` - 대신 `Group.externalAuditEventStreamingDestinations`를 사용합니다.
- `Group.googleCloudLoggingConfigurations` - 대신 `gcpLogging` 카테고리와 함께 `Group.externalAuditEventStreamingDestinations`를 사용합니다.
- `Group.amazonS3Configurations` - 대신 `amazonS3` 카테고리와 함께 `Group.externalAuditEventStreamingDestinations`를 사용합니다.

새로운 통합 스트리밍 대상 API는 `category` 매개변수를 사용하여 단일 엔드포인트 집합을 통해 모든 대상 카테고리 (HTTP, Google Cloud Logging, Amazon S3)를 지원합니다.

### 레거시 인스턴스 수준 감사 이벤트 스트리밍 대상 GraphQL API {#legacy-instance-level-audit-event-streaming-destination-graphql-apis}

- GitLab 18.10에서 발표됨
- GitLab 20.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/groups/gitlab-org/-/work_items/12339)를 참조하세요.

다음 인스턴스 수준 GraphQL 감사 이벤트 스트리밍 대상 API는 중단되었으며 GitLab 20.0에서 제거될 예정입니다.

중단된 뮤테이션:

- `instanceExternalAuditEventDestinationCreate` - 대신 `instanceAuditEventStreamingDestinationsCreate`를 사용합니다.
- `instanceExternalAuditEventDestinationDestroy` - 대신 `instanceAuditEventStreamingDestinationsDelete`를 사용합니다.
- `instanceExternalAuditEventDestinationUpdate` - 대신 `instanceAuditEventStreamingDestinationsUpdate`를 사용합니다.
- `instanceGoogleCloudLoggingConfigurationCreate` - 대신 `gcpLogging` 카테고리와 함께 `instanceAuditEventStreamingDestinationsCreate`를 사용합니다.
- `instanceGoogleCloudLoggingConfigurationDestroy` - 대신 `instanceAuditEventStreamingDestinationsDelete`를 사용합니다.
- `instanceGoogleCloudLoggingConfigurationUpdate` - 대신 `instanceAuditEventStreamingDestinationsUpdate`를 사용합니다.
- `auditEventsInstanceAmazonS3ConfigurationCreate` - 대신 `amazonS3` 카테고리와 함께 `instanceAuditEventStreamingDestinationsCreate`를 사용합니다.
- `auditEventsInstanceAmazonS3ConfigurationDelete` - 대신 `instanceAuditEventStreamingDestinationsDelete`를 사용합니다.
- `auditEventsInstanceAmazonS3ConfigurationUpdate` - 대신 `instanceAuditEventStreamingDestinationsUpdate`를 사용합니다.
- `auditEventsStreamingInstanceHeadersCreate` - `instanceAuditEventStreamingDestinationsUpdate`를 사용하여 스트리밍 대상 구성으로 헤더를 구성합니다.
- `auditEventsStreamingInstanceHeadersDestroy` - `instanceAuditEventStreamingDestinationsUpdate`를 사용하여 스트리밍 대상 구성으로 헤더를 구성합니다.
- `auditEventsStreamingInstanceHeadersUpdate` - `instanceAuditEventStreamingDestinationsUpdate`를 사용하여 스트리밍 대상 구성으로 헤더를 구성합니다.
- `auditEventsStreamingDestinationInstanceEventsAdd` - 대신 `auditEventsInstanceDestinationEventsAdd`를 사용합니다.
- `auditEventsStreamingDestinationInstanceEventsRemove` - 대신 `auditEventsInstanceDestinationEventsRemove`를 사용합니다.

중단된 쿼리 필드:

- `instanceExternalAuditEventDestinations` - 대신 `auditEventsInstanceStreamingDestinations`를 사용합니다.
- `instanceGoogleCloudLoggingConfigurations` - 대신 `gcpLogging` 카테고리와 함께 `auditEventsInstanceStreamingDestinations`를 사용합니다.
- `auditEventsInstanceAmazonS3Configurations` - 대신 `amazonS3` 카테고리와 함께 `auditEventsInstanceStreamingDestinations`를 사용합니다.

새로운 통합 스트리밍 대상 API는 `category` 매개변수를 사용하여 단일 엔드포인트 집합을 통해 모든 대상 카테고리 (HTTP, Google Cloud Logging, Amazon S3)를 지원합니다.

### NGINX Ingress, HAProxy, 및 Traefik 차트 지원 {#support-for-nginx-ingress-haproxy-and-traefik-charts}

- GitLab 18.9에서 발표됨
- GitLab 20.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/590799)를 참조하세요.

GitLab Helm 차트는 Kubernetes Gateway API를 사용하는 기본 Envoy Gateway의 대안으로 여러 Ingress 컨트롤러를 번들로 제공합니다.

이러한 번들 Ingress 컨트롤러, 즉 NGINX Ingress, HAProxy, 및 Traefik은 GitLab Helm 차트 및 GitLab Operator에서 제거됩니다. Ingress 사용은 GitLab Helm 차트 및 GitLab Operator에서 계속 지원되지만 외부 Ingress 컨트롤러를 배포해야 합니다.

번들된 Envoy Gateway 및 Gateway API로 마이그레이션할 것을 권장합니다. 또는 [외부 Ingress 컨트롤러 및 클래스](https://docs.gitlab.com/charts/charts/globals/#configure-ingress-settings)를 배포하고 구성할 수 있습니다.

### `--master` 옵션 `gitlab-ctl patroni failover` 및 `switchover` {#--master-option-for-gitlab-ctl-patroni-failover-and-switchover}

- GitLab 19.4에서 발표됨
- GitLab 20.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/work_items/9467)를 참조하세요.

`gitlab-ctl patroni failover` 및 `gitlab-ctl patroni switchover` 명령의 `--master` 옵션은 중단되었으며 GitLab 20.0에서 제거될 예정입니다. 두 명령 모두 GitLab 19.4 기준으로 `--leader`를 허용하며, 이는 `patronictl`가 사용하는 옵션 이름과 일치합니다.

마이그레이션하려면 이러한 명령을 호출하는 스크립트 및 런북에서 `--master`을 `--leader`로 바꿉니다. 옵션은 같은 값을 허용합니다: 현재 리더 노드의 이름입니다. 제거될 때까지 `--master`은 동작을 유지하고 기능 중단 경고를 인쇄합니다.

### `kpt` 기반 `agentk` 중단됨 {#kpt-based-agentk-is-deprecated}

- GitLab 17.9에서 발표됨
- GitLab 20.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent/-/issues/656)를 참조하세요.

Kubernetes용 에이전트의 `kpt` 기반 설치에 대한 지원을 제거합니다. `kpt` 패키지가 손상되고 오래되었습니다. 2022년 이후로 유지보수되지 않았으며, 그 이후 Helm 차트에 추가된 기능이 없으며, 알려진 사용자가 없습니다. 대신 지원되는 설치 방법 중 하나로 에이전트를 설치해야 합니다:

- Helm (권장)
- GitLab CLI
- Flux

`kpt`에서 Helm으로 마이그레이션하려면 [에이전트 설치 설명서](https://docs.gitlab.com/user/clusters/agent/install/)를 따라 `kpt` 배포 `agentk` 인스턴스를 덮어쓰세요.

## GitLab 19.6 {#gitlab-196}

### Bitbucket Cloud 이슈 및 wiki 가져오기 {#bitbucket-cloud-issue-and-wiki-import}

- GitLab 19.1에서 발표됨
- GitLab 19.6에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/601061)를 참조하세요.

Atlassian은 [2026년 8월 20일에 Bitbucket Cloud Issues 및 Wikis 종료](https://community.atlassian.com/forums/Bitbucket-articles/Announcing-sunset-of-Bitbucket-Issues-and-Wikis/ba-p/3193882)하고 있습니다. 그 이후 기본 API 엔드포인트가 제거되므로 GitLab은 더 이상 Bitbucket Cloud에서 이슈 또는 wiki를 가져올 수 없습니다.

GitLab 19.3에서는 Bitbucket Cloud importer가 API 제거를 정상적으로 처리하고 이슈 및 wiki를 건너뛸 계획입니다. GitLab 19.6에서는 이슈 및 wiki에 대한 가져오기 코드를 제거할 계획입니다.

Bitbucket 이슈 데이터가 필요한 사용자는 2026년 8월 20일 기한 전에 가져오기를 완료하거나 Bitbucket에서 내보낸 후 [CSV 가져오기](https://docs.gitlab.com/user/project/issues/csv_import/)를 사용해야 합니다. wiki의 경우 기한 이전에 Bitbucket wiki 리포지토리를 로컬로 복제합니다.

## GitLab 19.5 {#gitlab-195}

### GraphQL `secretPermissionUpdate` 및 `secretPermissionDelete` 뮤테이션 {#graphql-secretpermissionupdate-and-secretpermissiondelete-mutations}

- GitLab 19.5에서 발표됨
- GitLab 19.5에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/630579)를 참조하세요.

GitLab Secrets Manager를 베타에서 일반 제공으로 이동하는 과정의 일부로, GitLab은 GitLab 19.5에서 `secretPermissionUpdate` 및 `secretPermissionDelete` GraphQL 뮤테이션을 제거합니다. 대신 `projectSecretsPermissionUpdate` 및 `projectSecretsPermissionDelete`를 사용합니다. 대체 뮤테이션은 이전 뮤테이션과 동일한 서비스를 호출합니다.

새로운 뮤테이션은 이전 `permissions` 인수를 대신하는 `actions` 인수를 취하며, 이전 인수는 소문자 문자열 값을 취했습니다. 새로운 `actions` 인수는 `SecretsManagementAction` 열거형을 취합니다. 이 열거형의 각 값은 대문자입니다. 각 이전 값을 새 값으로 매핑합니다:

- `"read"`은 `READ`로 매핑됩니다.
- `"create"` 자체로 `CREATE`로 매핑됩니다.
- `"update"`, `"create"` 포함 여부 상관없이 `WRITE`으로 매핑됩니다.
- `"delete"`은 `DELETE`로 매핑됩니다.

응답 모양도 변경됩니다. 코드를 업데이트하여 이러한 변경 사항을 반영합니다:

- 페이로드 필드 이름이 `secretPermission`에서 `secretsPermission`로 변경됩니다.
- 페이로드 유형 이름이 `SecretPermission`에서 `ProjectSecretsPermission`로 변경됩니다.
- 새 유형에 `permissions` 필드가 없습니다. 대신 `actions` 필드를 읽습니다.

## GitLab 19.3 {#gitlab-193}

### REST API가 정수 경로 매개변수의 숫자가 아닌 ID에 대해 400을 반환합니다 {#rest-api-returns-400-for-non-numeric-ids-on-integer-path-parameters}

- GitLab 19.3에서 발표됨
- GitLab 19.3에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/605824)를 참조하세요.

여러 REST API 엔드포인트는 이전에 정수 형식의 경로 매개변수에서 숫자가 아닌 값 또는 여러 값을 사전 검증 없이 허용했습니다. 명확한 오류 대신 이러한 요청은 일관성 없는 응답(`401 Unauthorized`, `404 Not Found` 또는 드문 잠재적 버그의 경우 `200 OK`)을 반환했습니다. 이제 매개변수 유형을 검증하고 `400 Bad Request`을 반환합니다.

마이그레이션하려면 각 요청마다 단일 숫자 ID를 보내세요. 정상적인 클라이언트는 이미 이를 수행하므로 올바른 형식의 요청에는 조치가 필요하지 않습니다.

## GitLab 19.2 {#gitlab-192}

### Advanced Search는 Self Managed Ultimate Tier에 필수입니다 {#advanced-search-is-required-for-self-managed-ultimate-tier}

- GitLab 18.11에서 발표됨
- GitLab 19.2에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/582417)를 참조하세요.

이제 Self Managed Ultimate Tier 고객이 [Advanced Search](https://docs.gitlab.com/integration/advanced_search/elasticsearch/)를 사용하여 Ultimate Tier 기능의 전체 제품군에 완전히 액세스할 수 있도록 **_요구_**합니다. GitLab은 Advanced Search 없이 깨지지 않지만 Advanced Search가 활성화되지 않으면 모든 Ultimate Tier 기능을 사용할 수 없습니다.

이전에는 특정 기능의 쿼리 성능을 향상시키는 방법으로 Advanced Search를 활성화하는 것을 **_권장_**했습니다. 이제 Advanced Search가 필요한 전체 기능을 구축하는 것이 우리가 요구하는 전달 속도와 품질을 충족하기 위한 기본이라고 확인했습니다.

Advanced Search를 사용하지 않으면 기존 기능이 깨지거나 성능이 저하되지 않습니다. 이것은 앞으로의 변경입니다: 새 기능은 Advanced Search 없이 지원되지 않을 수 있습니다. Ultimate Tier GA 기능은 이제 전체 또는 부분 기능에 대해 Advanced Search에 대한 엄격한 요구사항이 있을 수 있습니다.

Advanced Search를 활성화하기 위한 지침은 [설명서에서 확인](https://docs.gitlab.com/user/search/advanced_search/)할 수 있습니다.

## GitLab 19.1 {#gitlab-191}

### 고급 검색에서 더 이상 지원되지 않는 Elasticsearch 7.x {#elasticsearch-7x-no-longer-supported-for-advanced-search}

- GitLab 18.10에서 발표됨
- GitLab 19.1에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/583544)를 참조하세요.

[Elasticsearch 7.x에 대한 유지보수 기간](https://www.elastic.co/support/eol)은 2026년 1월 15일에 종료되었습니다. GitLab Self-Managed의 경우 관리자는 고급 검색을 사용하기 위해 Elasticsearch 인스턴스를 업그레이드해야 합니다.

### Amazon Linux 2에 대한 Linux 패키지 지원 {#linux-package-support-for-amazon-linux-2}

- GitLab 18.9에서 발표됨
- GitLab 19.1에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/590802)를 참조하세요.

GitLab 19.1에서 Linux 패키지에 대한 Amazon Linux 2 (AL2) 패키지 빌드를 제거합니다.

Amazon Linux 2는 2026년 6월에 수명 종료에 도달하며 그 이후로는 보안 업데이트를 더 이상 받지 않을 예정입니다. 저희 [Linux 패키지 지원 플랫폼 정책](https://docs.gitlab.com/install/package/#supported-platforms)에 따라, 최소 6개월의 공지 기간을 두고 공급업체가 운영 체제 지원을 중단하면 패키지 빌드를 중단합니다.

현재 Amazon Linux 2에서 GitLab을 실행 중인 경우, GitLab 19.1로 업그레이드하기 전에 Amazon Linux 2023 (AL2023) 또는 다른 [지원되는 운영 체제](https://docs.gitlab.com/install/package/#supported-platforms)로 마이그레이션해야 합니다. Amazon은 AL2에서 AL2023으로 이동하는 데 도움이 되는 [마이그레이션 설명서](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/using-features.migration-al.generic.from-al2.html)를 제공합니다.

## GitLab 19.0 {#gitlab-190}

### 컨테이너 레지스트리용 Azure 스토리지 드라이버 {#azure-storage-driver-for-the-container-registry}

- GitLab 17.10에서 발표됨
- GitLab 19.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/523096)를 참조하세요.

컨테이너 레지스트리의 레거시 Azure 스토리지 드라이버는 GitLab 17.10에서 중단되었으며 GitLab 19.0에서 제거될 예정입니다. 컨테이너 레지스트리에 Azure 객체 저장소를 사용하고 새 드라이버를 더 일찍 사용하고 싶은 경우, 구성을 새로운 `azure_v2` 드라이버를 사용하도록 업데이트해야 합니다. GitLab 19.0에서 중단된 Azure 드라이버는 `azure_v2` 드라이버의 별칭이 되며 수동 조치가 필요하지 않습니다.

`azure_v2` 스토리지 드라이버는 개선된 안정성, 더 나은 성능, 그리고 레거시 드라이버와 비교하여 더 유지 가능한 코드베이스를 제공합니다. 이러한 개선 사항은 레지스트리 사용량이 증가함에 따라 성능 문제를 방지하는 데 도움이 됩니다.

`azure_v2` 드라이버로 마이그레이션하려면:

1. 레지스트리 구성 파일을 업데이트하여 레거시 `azure` 드라이버 대신 `azure_v2` 드라이버를 사용합니다.
1. 필요에 따라 새 드라이버의 구성 설정을 조정합니다.
1. 프로덕션 환경에 배포하기 전에 비프로덕션 환경에서 새 구성을 테스트합니다.

저장소 드라이버 구성을 업데이트하는 방법에 대한 자세한 내용은 [객체 저장소 사용](https://docs.gitlab.com/administration/packages/container_registry/#use-object-storage)을 참조하세요.

### 컨테이너 레지스트리 AWS S3 서명 버전 2 지원 {#container-registry-aws-s3-signature-version-2-support}

- GitLab 17.8에서 발표됨
- GitLab 19.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/container-registry/-/issues/1449)를 참조하세요.

컨테이너 레지스트리에서 Amazon S3 Signature Version 2를 사용한 요청 인증 지원은 GitLab 17.8에서 중단되었으며 GitLab 19.0에서 제거될 계획입니다.

AWS SDK v2 기반의 새로운 S3v2 저장소 드라이버 (GitLab 17.10부터 베타로 사용 가능하며 19.0에서 기본값이 됨)는 Signature Version 4만 지원합니다. S3v2 드라이버가 기본값이 되면, Signature Version 2 구성 설정 (예: `v4auth: false`)은 투명하게 무시됩니다.

S3v2이 기본 드라이버가 되는 GitLab 버전으로 업그레이드하기 전에 Signature Version 4로 마이그레이션할 수 있습니다. 이 변경을 위해서는 S3 버킷 구성 설정을 업데이트하고 GitLab 컨테이너 레지스트리 설정이 Signature Version 4와 호환되는지 확인해야 합니다.

마이그레이션하려면:

1. GitLab 컨테이너 레지스트리 설정에서 [S3 저장소 백엔드 구성](https://docs.gitlab.com/administration/packages/container_registry/#use-object-storage)을 확인합니다.
1. `v4auth`이 `false`로 설정된 경우 옵션을 제거합니다.
1. 기존 자격 증명이 v4 인증과 작동하는지 확인합니다.

이러한 변경을 수행한 후 문제가 발생하면 AWS 자격 증명을 다시 생성해보세요.

### 인증되지 않은 Projects API 요청에 대한 페이지 제한 적용 {#enforce-page-limit-for-unauthenticated-projects-api-requests}

- GitLab 18.9에서 발표됨
- GitLab 19.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/585176)를 참조하세요.

플랫폼 안정성을 유지하고 모든 고객을 위한 최적의 성능을 보장하기 위해 인증되지 않은 Projects API 요청에 최대 오프셋 제한을 적용하고 있습니다. 오프셋 제한은 GitLab.com에만 적용됩니다. GitLab Self-Managed 및 GitLab Dedicated에서는 기능 플래그 뒤에서 기본적으로 오프셋 제한이 비활성화됩니다.

**변경되는 사항**

Projects List REST API에 대한 모든 인증되지 않은 요청에 최대 오프셋 제한 50,000이 적용됩니다. 예를 들어, 페이지당 20개의 결과를 검색할 때 `page` 매개변수는 2,500개 페이지로 제한됩니다.

더 많은 데이터에 액세스해야 하는 워크플로우는 키셋 기반 페이지 매김 매개변수를 사용해야 합니다.

**왜 중요한가**

이 제한은 리소스 사용률을 효과적으로 관리하여 GitLab.com 전체에서 일관된 서비스 품질과 성능을 보장합니다.

### SUSE 배포판에 대한 Linux 패키지 지원 {#linux-package-support-for-suse-distributions}

- GitLab 18.9에서 발표됨
- GitLab 19.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/590801)를 참조하세요.

GitLab 19.0에서 SUSE 배포판에 대한 지원을 중단하고 있습니다. 이것은 다음에 영향을 줍니다:

- openSUSE Leap 15.6
- SUSE Linux Enterprise Server 12.5
- SUSE Linux Enterprise Server 15.6

openSUSE Leap 15.6이 수명 종료에 접근하고 있습니다. SUSE Linux Enterprise Server는 SUSE를 통해 장기 서비스로 계속 지원되지만, GitLab 고객 중 채택이 너무 낮아 지속적인 지원이 상업적으로 실행 가능하지 않습니다.

Linux 패키지를 사용하는 SUSE 배포판의 고객은 GitLab 버전 `18.11.x` 이상으로 업그레이드할 수 없습니다.

이러한 배포판 중 하나에 있는 고객을 위해, 기존 배포판에서 [GitLab의 Docker 배포](https://docs.gitlab.com/install/docker/installation/)로 마이그레이션하는 것이 좋습니다. 이렇게 하면 GitLab 업그레이드를 계속 받기 위해 다른 Linux 배포판으로 마이그레이션할 필요가 없습니다.

**업데이트**: [SLES 12.5의 RPM 패키지 크기 제약](https://gitlab.com/gitlab-org/omnibus-gitlab/-/work_items/9716)으로 인해 [Mattermost](https://docs.gitlab.com/update/deprecations/#mattermost-bundled-with-linux-package) 및 [Spamcheck](https://docs.gitlab.com/update/deprecations/#spamcheck-support-in-the-linux-package-and-gitlab-helm-chart)은 GitLab 18.11에서 SLES 12.5 패키지에서 제거되었으며 GitLab 19.0의 모든 배포판에서 제거될 예정입니다.

### Ubuntu 20.04에 대한 Linux 패키지 지원 {#linux-package-support-for-ubuntu-2004}

- GitLab 17.9에서 발표됨
- GitLab 19.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8915)를 참조하세요.

Ubuntu 20.04에 대한 Ubuntu 표준 지원은 [2025년 5월에 종료](https://wiki.ubuntu.com/Releases)되었습니다.

저희 [Linux 패키지 지원 플랫폼 정책](https://docs.gitlab.com/install/package/#supported-platforms)에 따라, 공급업체가 운영 체제 지원을 중단하면 패키지 빌드를 중단합니다.

GitLab 19.0부터 Linux 패키지 설치를 위해 Ubuntu 20.04 배포판에 대한 패키지를 더 이상 제공하지 않습니다. GitLab 18.11은 Ubuntu 20.04용 Linux 패키지를 제공하는 마지막 GitLab 버전입니다.

현재 Ubuntu 20.04에서 GitLab을 실행 중인 경우, GitLab 19.0으로 업그레이드하기 전에 Ubuntu 22.04 또는 다른 [지원되는 운영 체제](https://docs.gitlab.com/install/package/#supported-platforms)로 업그레이드해야 합니다. Canonical은 마이그레이션에 도움이 되는 [업그레이드 가이드](https://documentation.ubuntu.com/server/how-to/software/upgrade-your-release/)를 제공합니다.

### Linux 패키지와 번들된 Mattermost {#mattermost-bundled-with-linux-package}

- GitLab 18.9에서 발표됨
- GitLab 19.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/590798)를 참조하세요.

GitLab 19.0에서 Linux 패키지에서 번들된 Mattermost를 제거할 계획입니다.

Mattermost는 2015년에 GitLab SSO 포함 오픈 소스 팀 메시징 솔루션으로 처음 번들되었습니다. 그 이후로 Mattermost는 자신의 패키징 및 배포 옵션을 상당히 성숙시켰으며, GitLab 고객 중 번들된 Mattermost의 채택은 상대적으로 낮게 유지되었습니다.

Mattermost v11을 사용하면 [Mattermost는 자신의 무료 제공에서 GitLab SSO를 중단](https://forum.mattermost.com/t/mattermost-v11-changes-in-free-offerings/25126)했습니다. 이 변경, Mattermost 독립 실행형 배포 옵션의 성숙함, 그리고 고객 기반에서의 낮은 채택을 감안할 때, Linux 패키지에서 Mattermost를 제거하고 있습니다.

현재 GitLab과 번들된 Mattermost를 사용 중인 경우, Mattermost 설명서의 [GitLab Omnibus에서 Mattermost 독립 실행형으로 마이그레이션](https://docs.mattermost.com/administration-guide/onboard/migrate-gitlab-omnibus.html)을 참조하여 마이그레이션 지침 및 사용 가능한 Mattermost 에디션을 확인하세요.

### Resource Owner Password Credentials Grant 중단됨 {#resource-owner-password-credentials-grant-is-deprecated}

- GitLab 18.0에서 발표됨
- GitLab 19.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/457353)를 참조하세요.

OAuth 흐름으로 Resource Owner Password Credentials (ROPC) Grant를 사용하는 것은 중단되었으며, 지원은 GitLab 19.0에서 완전히 제거될 예정입니다. 관리자가 자신의 인스턴스에서 클라이언트 자격 증명만 사용하도록 이 권한 유형을 활성화하거나 비활성화할 수 있는 설정을 추가했습니다. 이를 통해 클라이언트 자격 증명 없이 ROPC 사용을 거부하려는 사용자가 19.0 이전에 그렇게 할 수 있습니다. ROPC는 19.0에서 완전히 제거되며 이후에는 클라이언트 자격 증명과 함께 사용될 수 없습니다.

GitLab은 보안 이유로 [2025년 4월 8일 이후로 GitLab.com에서 ROPC에 대한 클라이언트 인증을 요구](https://about.gitlab.com/blog/improving-oauth-ropc-security-on-gitlab-com/)했습니다. ROPC 지원을 완전히 제거하면 보안이 OAuth RFC 버전 2.1과 일치합니다.

### 컨테이너 레지스트리용 S3 저장소 드라이버 (AWS SDK v1) {#s3-storage-driver-aws-sdk-v1-for-the-container-registry}

- GitLab 17.10에서 발표됨
- GitLab 19.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/523095)를 참조하세요.

AWS SDK v1을 사용하는 컨테이너 레지스트리용 S3 저장소 드라이버는 중단되었으며 GitLab 19.0에서 제거될 예정입니다. 컨테이너 레지스트리에 S3 객체 저장소를 사용하고 새 드라이버를 더 빨리 사용하려면, 구성을 새로운 `s3_v2` 드라이버를 사용하도록 업데이트해야 합니다. GitLab 19.0에서 중단된 s3 드라이버는 `s3_v2` 드라이버의 별칭이 되며, 수동 조치가 필요하지 않습니다.

`s3_v2` 저장소 드라이버는 AWS SDK v2를 기반으로 하며 향상된 성능, 더 나은 보안, 그리고 AWS의 지속적인 지원을 제공합니다. 이것은 2025년 5월부터 사용 가능하여 2025년 7월 31일에 지원이 종료되는 중단된 [AWS SDK v1](https://aws.amazon.com/blogs/developer/announcing-end-of-support-for-aws-sdk-for-go-v1-on-july-31-2025/)을 대체합니다.

`s3_v2` 드라이버는 더 이상 서명 알고리즘 v2를 지원하지 않습니다. 구성에서 `v4auth: false` 옵션이 설정된 경우 `s3_v2` 드라이버에 의해 투명하게 무시되며 더 안전한 V4 알고리즘이 사용됩니다. `s3_v2` 드라이버로 마이그레이션하려면:

1. 레지스트리 구성 파일을 업데이트하여 `s3` 대신 `s3_v2` 구성을 사용합니다.
1. 아직 수행하지 않았다면 인증을 위해 Signature Version 2에서 Signature Version 4로 이동합니다. AWS SDK v2는 Signature Version 4만 지원합니다.
1. 프로덕션 환경에 배포하기 전에 비프로덕션 환경에서 구성을 테스트합니다.

AWS S3에서 드라이버 변경은 클라이언트가 레지스트리 블롭을 다운로드하는 데 사용하는 사전 서명된 URL의 호스트 이름을 변경할 수도 있습니다. AWS SDK v2는 구성된 영역에 대한 S3 엔드포인트를 확인하므로 사전 서명된 URL은 전역 `s3.amazonaws.com` 호스트 이름 대신 `s3.us-east-1.amazonaws.com` 같은 지역 호스트 이름을 사용할 수 있습니다. 네트워크가 아웃바운드 트래픽을 제한하는 경우, 업그레이드하기 전에 프록시 또는 방화벽 허용 목록을 업데이트하여 지역 호스트 이름을 포함시키세요. 그렇지 않으면 이미지 풀이 `403 Forbidden` 응답으로 실패합니다.

저장소 드라이버 구성을 업데이트하는 방법에 대한 자세한 내용은 [객체 저장소 사용](https://docs.gitlab.com/administration/packages/container_registry/#use-object-storage)을 참조하세요.

### Slack 슬래시 명령 {#slack-slash-commands}

- GitLab 18.7에서 발표됨
- GitLab 19.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/569345)를 참조하세요.

Slack 슬래시 명령 통합은 같은 기능을 제공하는 [GitLab for Slack 앱](https://docs.gitlab.com/user/project/integrations/gitlab_slack_application/)을 위해 중단되었으며, 더 안전한 통합 방법을 제공합니다.

GitLab 19.0부터 사용자는 더 이상 Slack 슬래시 명령 통합을 구성하거나 사용할 수 없습니다. 이 통합은 GitLab Self-Managed 및 GitLab Dedicated 인스턴스에서만 사용 가능합니다. GitLab.com에 있는 경우 조치할 필요가 없습니다.

GitLab Self-Managed 또는 GitLab Dedicated에 있는 경우, 영향을 받는지 확인하려면 [이슈 569345](https://gitlab.com/gitlab-org/gitlab/-/work_items/569345#am-i-impacted)를 참조하세요.

### Linux 패키지 및 GitLab Helm 차트의 Spamcheck 지원 {#spamcheck-support-in-the-linux-package-and-gitlab-helm-chart}

- GitLab 18.9에서 발표됨
- GitLab 19.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/590796)를 참조하세요.

GitLab 19.0에서 Linux 패키지 및 GitLab Helm 차트에서 [Spamcheck](https://docs.gitlab.com/administration/reporting/spamcheck/)을 제거합니다.

Spamcheck은 공개 GitLab 인스턴스의 스팸을 퇴치하기 위한 서비스입니다. 본질적으로 이 기능은 주로 대규모 공개 인스턴스와 관련이 있으며, 이는 고객 기반의 극소수 사례입니다.

낮은 채택과 독립 실행형 배포 옵션의 가용성을 고려하여 Linux 패키지 및 GitLab Helm 차트에서 Spamcheck을 제거하고 있습니다. Spamcheck을 사용하지 않는 고객은 이 변경의 영향을 받지 않습니다. 제거는 패키지 크기 및 종속성 공간 (따라서 보안)을 줄여 대부분의 고객에게 도움이 됩니다.

현재 번들된 Spamcheck을 사용 중인 경우, [Docker](https://gitlab.com/gitlab-org/gl-security/security-engineering/security-automation/spam/spamcheck)를 사용하여 별도로 배포할 수 있습니다.

데이터 마이그레이션은 필요하지 않습니다. 구성 지침은 연결된 설명서에서 확인할 수 있습니다.

### NGINX Ingress에 대한 지원 {#support-for-nginx-ingress}

- GitLab 18.9에서 발표됨
- GitLab 19.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/590800)를 참조하세요.

GitLab Helm 차트는 현재 NGINX Ingress를 기본 네트워킹 구성 요소로 번들합니다. NGINX Ingress가 2026년 3월에 수명 종료에 도달하면서 Gateway API와 Envoy Gateway로 전환하고 있습니다.

GitLab 19.0부터 Gateway API와 번들된 Envoy Gateway가 기본 구성이 됩니다. Envoy Gateway로의 마이그레이션이 배포에 가능하지 않은 경우, 번들된 NGINX Ingress를 명시적으로 다시 활성화할 수 있으며, 이는 GitLab 20.0에서 계획된 제거까지 사용 가능하게 유지됩니다.

이 변경은 Linux 패키지의 NGINX 또는 외부 관리 Ingress 또는 Gateway API 컨트롤러를 사용하는 GitLab Helm 차트 및 GitLab Operator 인스턴스에는 영향을 주지 않습니다.

전체 제거까지 포크된 NGINX Ingress 차트 및 빌드에 대해 최선의 보안 유지보수를 제공합니다. 원활한 전환을 보장하려면 제공된 Gateway API 솔루션으로 마이그레이션하거나 외부 관리 Ingress 컨트롤러를 계획할 것을 권장합니다. 단계별 지침은 [Envoy Gateway 마이그레이션 가이드](https://docs.gitlab.com/charts/installation/migration/envoy_gateway_migration/)를 참조하세요.

### PostgreSQL 16 지원 {#support-for-postgresql-16}

- GitLab 18.9에서 발표됨
- GitLab 19.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/589774)를 참조하세요.

GitLab은 PostgreSQL에 대해 [연간 업그레이드 주기](https://handbook.gitlab.com/handbook/engineering/data-engineering/database-excellence/database-frameworks/postgresql-upgrade-cadence/)를 따릅니다.

PostgreSQL 16에 대한 지원은 GitLab 19.0에서 제거될 예정입니다. GitLab 19.0에서는 PostgreSQL 17이 최소 필수 PostgreSQL 버전이 됩니다.

PostgreSQL 17은 GitLab 18.9부터 사용 가능하며, GitLab 19.0에서 PostgreSQL 16이 제거되기 전에 언제든지 업그레이드할 수 있습니다.

Linux 패키지를 사용하여 설치한 단일 PostgreSQL 인스턴스를 실행 중인 경우, 18.11에서 자동 업그레이드가 시도될 수 있습니다. 업그레이드를 수용할 충분한 디스크 공간이 있는지 확인하세요.

자세한 내용은 [패키지된 PostgreSQL 서버 업그레이드](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server)를 참조하세요.

### Redis 6 지원 {#support-for-redis-6}

- GitLab 18.10에서 발표됨
- GitLab 19.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/585839)를 참조하세요.

GitLab 19.0에서는 보안 및 지원 가능한 인프라 스택을 유지하기 위한 약속의 일부로 Redis 6에 대한 지원을 제거할 계획입니다.

GitLab 19.0으로 업그레이드하기 전에 Redis 7.0 이상 또는 Valkey 7.2로 마이그레이션합니다. Redis 7.2 또는 Valkey 7.2를 권장합니다. Redis 7.0은 업스트림에서 수명 종료 (EOL)에 도달했지만 경우에 따라 Amazon ElastiCache for Redis 7.1과 같은 공급업체에 의해 적극적으로 유지됩니다. 이는 Redis 7.0을 기반으로 합니다.

Linux 패키지에 포함된 번들 Redis는 GitLab 16.2부터 Redis 7을 사용했으며 영향을 받지 않습니다. Redis 6 배포를 외부에서 사용하는 GitLab Self-Managed 인스턴스만 마이그레이션해야 합니다.

외부 Redis 6 배포를 마이그레이션하기 위한 다음 리소스를 참조하세요:

- **AWS ElastiCache**: AWS에서는 ElastiCache for Redis 7.2를 사용할 수 없습니다. [Amazon ElastiCache for Valkey 7.2](https://aws.amazon.com/elasticache/what-is-valkey/)로 마이그레이션합니다 (권장). ElastiCache for Redis 7.1은 Redis 7.0을 기반으로 하며 작동하는 것으로 알려져 있습니다. 사용 가능한 업그레이드 경로는 [AWS ElastiCache 설명서](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/engine-versions.html)를 참조하세요.
- **GCP Memorystore**: Redis 6 인스턴스를 Redis 7.2 또는 Valkey 7.2로 업그레이드합니다. 사용 가능한 업그레이드 경로는 [GCP Memorystore 설명서](https://docs.cloud.google.com/memorystore/docs/redis/supported-versions)를 참조하세요.
- **Azure Cache for Redis**: Azure에서는 관리형 Redis 7.2 또는 Valkey 7.2 옵션을 현재 사용할 수 없습니다. Azure VMs 또는 AKS에서 Redis 7.2 또는 Valkey 7.2를 자체 호스팅할 수 있습니다. GitLab Linux 패키지 설치 방법을 사용할 수도 있으며, 이는 Valkey 7.2를 지원합니다.
- **자체 호스팅**: Redis 6 인스턴스를 Redis 7.2 또는 Valkey 7.2로 업그레이드합니다.

자세한 내용은 [요구사항 설명서](https://docs.gitlab.com/install/requirements/)를 참조하세요.

### GitLab Helm 차트의 번들된 PostgreSQL, Redis, 및 MinIO에 대한 지원 {#support-for-bundled-postgresql-redis-and-minio-in-gitlab-helm-chart}

- GitLab 18.9에서 발표됨
- GitLab 19.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/590797)를 참조하세요.

GitLab Helm 차트는 Bitnami PostgreSQL, Bitnami Redis, 및 공식 MinIO 차트의 포크를 번들하여 GitLab 설정을 더 쉽게 합니다. 라이선싱, 프로젝트 유지보수, 및 공개 이미지 가용성의 여러 변경으로 인해 이러한 구성 요소는 GitLab Helm 차트 및 GitLab Operator에서 대체 없이 제거될 예정입니다.

이러한 차트는 현재 기본적으로 활성화되어 있지만 프로덕션 사용에는 권장되지 않는 것으로 명시적으로 문서화되어 있습니다. 이들의 유일한 목적은 빠른 설정 개념 증명 및 테스트 환경을 활성화하는 것입니다.

번들된 PostgreSQL, Redis, 또는 MinIO를 사용하여 인스턴스를 실행 중인 경우, [마이그레이션 가이드](https://docs.gitlab.com/charts/installation/migration/bundled_chart_migration/)를 확인하세요.

Linux 패키지에서 제공하는 Redis 및 PostgreSQL은 이 변경의 영향을 받지 않습니다.

### `ci_job_token_scope_enabled` 프로젝트 API 속성은 중단됨 {#the-ci_job_token_scope_enabled-projects-api-attribute-is-deprecated}

- GitLab 16.4에서 발표됨
- GitLab 19.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/423091)를 참조하세요.

[이 프로젝트에서 액세스 제한](https://docs.gitlab.com/update/deprecations/#cicd-job-token---limit-access-from-your-project-setting-removal) CI/CD 작업 토큰 프로젝트 설정은 18.0에서 제거되었습니다. 관련된 [프로젝트 API](https://docs.gitlab.com/api/projects/)의 `ci_job_token_scope_enabled` 속성은 이제 중단되었으며 항상 `false`를 반환하므로 19.0에서 제거될 예정입니다. 작업 토큰 액세스를 제어하려면 [CI/CD 작업 토큰 프로젝트 설정](https://docs.gitlab.com/ci/jobs/ci_job_token/#control-job-token-access-to-your-project)을 사용합니다.

### `heroku/builder:22` 이미지는 중단됨 {#the-herokubuilder22-image-is-deprecated}

- GitLab 17.4에서 발표됨
- GitLab 19.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/cluster-integration/auto-build-image/-/issues/79)를 참조하세요.

클라우드 네이티브 빌드팩 (CNB) 빌더 이미지는 Auto DevOps Build 프로젝트에서 `heroku/builder:24`로 업데이트되었습니다. 대부분의 경우 변경이 파괴적이지 않을 것으로 예상되지만, 일부 Auto DevOps 사용자, 특히 Auto Build 사용자에게는 호환성을 깨는 변경일 수 있습니다. 워크로드의 영향을 더 잘 이해하려면 다음을 검토하세요:

- [Heroku-24 스택 릴리스 정보](https://devcenter.heroku.com/articles/heroku-24-stack#what-s-new)
- [Heroku-24 스택 업그레이드 정보](https://devcenter.heroku.com/articles/heroku-24-stack#upgrade-notes)
- [Heroku 스택 패키지](https://devcenter.heroku.com/articles/stack-packages)

파이프라인이 [Auto DevOps의 Auto Build 스테이지](https://docs.gitlab.com/topics/autodevops/stages/#auto-build)에서 제공하는 [`auto-build-image`](https://gitlab.com/gitlab-org/cluster-integration/auto-build-image)을 사용하는 경우 이 변경이 영향을 줍니다.

GitLab 19.0 후에 `heroku/builder:22`를 계속 사용하려면, `AUTO_DEVOPS_BUILD_IMAGE_CNB_BUILDER`를 `heroku/builder:22`로 설정합니다.

### Explore 프로젝트 페이지의 Trending 탭 중단 {#trending-tab-in-explore-projects-page-is-deprecated}

- GitLab 18.8에서 발표됨
- GitLab 19.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/groups/gitlab-org/-/work_items/18493)를 참조하세요.

**Trending** 탭 **탐색** > **프로젝트** 및 관련된 GraphQL 인수는 GitLab 18.8에서 중단되었으며 GitLab 19.0에서 제거될 예정입니다. GitLab 19.0 릴리스 이전 달에 **Trending** 탭은 GitLab.com에서 **활성** 탭으로 리디렉션되며 별을 내림차순으로 정렬됩니다.

**제거되는 항목**

- **탐색** > **프로젝트** 페이지의 **Trending** 탭
- 다음 GraphQL 유형의 추세 인수:
  - `Query.adminProjects`
  - `Query.projects`
  - `Organization.projects`

**이 변경을 하는 이유**

추세 알고리즘은 공개 프로젝트만 고려하므로 주로 내부 또는 비공개 가시성을 사용하는 GitLab Self-Managed 인스턴스에서 효과가 없습니다. 알고리즘의 제한 사항과 검색 기능 부족으로 인해 Self-Managed 사용자의 명시적 제거 요청이 발생했습니다. 상당한 개선에 투자하는 대신 기존 발견 메커니즘을 개선하는 데 리소스를 집중하고 있습니다.

**조치 필요**

UI 사용자: **Trending** 탭은 19.0에서 완전히 제거되기 전에 다음 호환성 깨는 변경 창 동안 액세스할 수 없게 됩니다. 최근에 업데이트되거나 가장 많은 별을 받은 프로젝트를 보려면 **활성** 탭을 사용할 것을 권장합니다.

### Bitbucket Cloud import GitLab API와 함께 앱 비밀번호 사용 {#using-app-passwords-with-bitbucket-cloud-import-gitlab-api}

- GitLab 18.9에서 발표됨
- GitLab 19.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/work_items/588961)를 참조하세요.

Atlassian은 Bitbucket Cloud에 대한 앱 비밀번호 (사용자 이름 및 비밀번호 인증)를 중단했으며 [2026년 6월 9일에 이 인증 방법이 작동하지 않을 것](https://www.atlassian.com/blog/bitbucket/bitbucket-cloud-transitions-to-api-tokens-enhancing-security-with-app-password-deprecation)으로 발표했습니다.

GitLab 19.0부터 GitLab API를 통해 Bitbucket Cloud에서 리포지토리를 가져오려면 [사용자 API 토큰](https://support.atlassian.com/organization-administration/docs/understand-user-api-tokens/)을 대신 사용해야 합니다.

Bitbucket Server에서 리포지토리를 가져오거나 GitLab UI를 통해 Bitbucket Cloud에서 가져오는 사용자는 영향을 받지 않습니다.

### `ciJobTokenScopeAddProject` GraphQL 뮤테이션은 중단됨 {#cijobtokenscopeaddproject-graphql-mutation-is-deprecated}

- GitLab 17.5에서 발표됨
- GitLab 19.0에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/474175)를 참조하세요.

GitLab 18.0에서 [CI/CD 작업 토큰에 대한 예정된 기본 동작 변경](https://docs.gitlab.com/update/deprecations/#default-cicd-job-token-ci_job_token-scope-changed)을 사용하면, 관련된 `ciJobTokenScopeAddProject` GraphQL 뮤테이션도 `ciJobTokenScopeAddGroupOrProject` 대신 중단하고 있습니다.

## GitLab 18.8 {#gitlab-188}

### 정적 규정 준수 위반 보고서 {#static-compliance-violations-report}

- GitLab 18.2에서 발표됨
- GitLab 18.8에서 제거 ([호환성 깨는 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/groups/gitlab-org/-/epics/12774)를 참조하세요.

기존 정적 규정 준수 위반 보고서는 GitLab 18.2에서 더 이상 사용되지 않으며 GitLab 18.8에서 제거됩니다.

정적 규정 준수 위반 보고서를 교체하려면:

- GitLab 17.11에서 [사용자 정의 규정 준수 프레임워크](https://docs.gitlab.com/user/compliance/compliance_frameworks/)를 출시했습니다.
- GitLab 18.2에서 새로운 [동적 규정 준수 위반 보고서](https://docs.gitlab.com/user/compliance/compliance_center/compliance_violations_report/)를 출시했습니다.

이러한 기능은 정적 위반 보고서와 동일한 기능을 모두 제공하지만 필요한 위반을 구성할 수 있습니다.

GitLab 18.8에서 정적 규정 준수 위반 보고서를 동적 보고서로 교체하며 규정 준수 프레임워크를 사용하여 요구 사항 및 통제에 대한 보다 정확한 보고를 제공합니다.

## GitLab 18.6 {#gitlab-186}

### GitLab Duo Self-Hosted에 대해 더 이상 사용되지 않는 초기 Mistral 모델 {#early-mistral-models-deprecated-for-gitlab-duo-self-hosted}

- GitLab 18.3에서 발표
- GitLab 18.6에서 지원 종료
- GitLab 18.6에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/557156)를 참조하세요.

GitLab 18.6에서 GitLab은 GitLab Duo Self-Hosted에서 사용할 Mistral 7B-it, Mixtral 8x7B 및 Mixtral 8x22B 모델에 대한 지원을 제거합니다. GitLab Duo Enterprise 고객은 GitLab Duo Self-Hosted에서 이러한 모델을 계속 사용할 수 있지만 이러한 모델을 사용하는 구성에 대한 기술 지원은 더 이상 받을 수 없습니다. GitLab Duo Self-Hosted는 Mistral Small 24B Instruct 2506을 계속 지원하며, 이는 일반적으로 사용 가능한 모든 GitLab Duo Self-Hosted 기능과 [완전히 호환되도록 검증](https://docs.gitlab.com/administration/gitlab_duo_self_hosted/supported_models_and_hardware_requirements/)되었습니다.

### Omnibus Linux 패키지와 함께 번들된 Prometheus 2.x {#prometheus-2x-bundled-with-the-omnibus-linux-package}

- GitLab 18.3에서 발표
- GitLab 18.6에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/9196)를 참조하세요.

Linux 패키지와 함께 번들된 Prometheus 2.x는 더 이상 사용되지 않으며 GitLab 18.6에서 최신 Prometheus 3.x 릴리스로 업데이트됩니다.

Prometheus 3은 새로운 로그 형식 및 더 엄격한 헤더 검증과 같은 잠재적으로 주요 변경 사항을 포함합니다. 자세한 내용은 [Prometheus 마이그레이션 가이드](https://prometheus.io/docs/prometheus/latest/migration/)를 참조하세요.

이 변경 사항은 GitLab Helm chart 설치에 영향을 주지 않습니다.

### 규정 준수 표준 준수 대시보드를 규정 준수 상태 대시보드로 교체 {#replace-compliance-standards-adherence-dashboard-with-compliance-status-dashboard}

- GitLab 17.11에서 발표
- GitLab 18.6에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/470834)를 참조하세요.

GitLab 17.11에서 출시했습니다:

- [사용자 정의 규정 준수 프레임워크](https://docs.gitlab.com/user/compliance/compliance_frameworks/).
- [규정 준수 상태 보고서](https://docs.gitlab.com/user/compliance/compliance_center/compliance_status_report/).

이러한 기능은 규정 준수 표준 준수 대시보드와 동일한 기능을 모두 제공하지만 필요한 준수를 구성할 수 있습니다.

GitLab 18.6에서 규정 준수 표준 준수 대시보드를 규정 준수 상태 대시보드로 교체하여 요구 사항 및 통제에 대한 보다 정확한 보고를 제공합니다.

### 정확한 코드 검색을 비활성화하기 위한 사용자 설정 {#user-setting-to-disable-exact-code-search}

- GitLab 18.3에서 발표
- GitLab 18.6에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/554933)를 참조하세요.

정확한 코드 검색을 비활성화하기 위한 사용자 설정은 이제 더 이상 사용되지 않습니다. GitLab.com에서는 프로필 기본 설정에서 정확한 코드 검색을 더 이상 비활성화할 수 없습니다.

정확한 코드 검색은 더 나은 사용자 경험을 제공하며 기존 검색 API와 호환됩니다. 이 사용자 설정은 모든 사용자가 향상된 검색 기능의 이점을 누리도록 GitLab 18.6에서 제거될 예정입니다.

## GitLab 18.5 {#gitlab-185}

### 고급 검색에서 OpenSearch 1.x에 대한 지원 {#support-for-opensearch-1x-in-advanced-search}

- GitLab 18.2에서 발표됨
- GitLab 18.5에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/554530)를 참조하세요.

[OpenSearch 1.x의 유지 관리 기간](https://opensearch.org/releases/#maintenance-policy)이 종료되었습니다. GitLab Self-Managed 및 GitLab Dedicated의 경우 관리자는 OpenSearch 인스턴스를 업그레이드하여 고급 검색을 사용해야 합니다.

## GitLab 18.4 {#gitlab-184}

### GitLab chart의 Bitnami PostgreSQL 및 Redis 이미지 {#bitnami-postgresql-and-redis-images-in-gitlab-chart}

- GitLab 18.4에서 발표
- GitLab 18.4에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/6089)를 참조하세요.

GitLab Helm chart 기본 구성은 PostgreSQL 및 Redis용 Bitnami 차트 및 컨테이너 이미지에 의존합니다. Bitnami는 2025년 9월 29일에 이러한 이미지를 무료 카탈로그에서 중단할 예정입니다. Brownouts는 2025년 8월 28일부터 이미지를 임시로 가져갑니다.

GitLab chart는 데모 및 테스트 목적으로만 Bitnami의 PostgreSQL 및 Redis를 번들합니다. 이들은 [지원되는 GitLab 참조 아키텍처](https://docs.gitlab.com/administration/reference_architectures/)의 일부가 아닙니다. 참조 아키텍처에 있거나 다른 공급업체의 패키지 또는 이미지로 외부 PostgreSQL 및 Redis를 배포한 경우 이 변경 사항의 영향을 **받지 않습니다**.

임시 해결책으로 GitLab은 chart 구성을 Bitnami 레거시 리포지토리로 마이그레이션했습니다. 그러나 패치되지 않은 GitLab chart 환경(GitLab 17.11, GitLab 18.0.5. GitLab 18.1.4 및 GitLab 18.2.1 이상)은 계속해서 더 이상 사용되지 않는 Bitnami 리포지토리에서 이미지를 끌어오며, 이는 9월 29일 이후 배포 실패를 야기할 수 있으며 brownout 단계 중에 배포 실패를 야기할 수도 있습니다.

영향을 받는 GitLab chart 구성을 실행 중인 경우 다음 중 하나를 수행해야 합니다:

- 지원되는 GitLab 참조 아키텍처로 마이그레이션합니다.
- 패치된 chart 버전으로 업그레이드합니다.
- chart 값에서 레거시 리포지토리를 구성합니다. 예를 보려면 [머지 리퀘스트 4421](https://gitlab.com/gitlab-org/charts/gitlab/-/merge_requests/4421)을 참조하세요.

앞으로 [Bitnami 구성 요소를 교체하거나 잠재적으로 GitLab chart에서 완전히 제거할 수 있는 대안을 평가](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/6089)할 것입니다. 자세한 내용은 [공식 Bitnami 공지](https://github.com/bitnami/charts/issues/35164)를 참조하세요.

## GitLab 18.3 {#gitlab-183}

### cert-manager Helm chart 업데이트 {#cert-manager-helm-chart-update}

- GitLab 18.0에서 발표됨
- GitLab 18.3에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/5928)를 참조하세요.

최신 cert-manager chart의 스키마 검증을 활성화하기 위해 GitLab Helm chart `certmanager.install` 값은 `installCertmanager`를 위해 더 이상 사용되지 않습니다. 스키마 정의는 GitLab chart의 `certmanager` 섹션 내에 추가한 추가 속성을 허용하지 않습니다.

GitLab 18.3(GitLab chart 9.3)에서 더 이상 사용되지 않는 값을 제거하고 번들된 cert-manager를 업데이트합니다.

이전에 `certmanager.install` 설정을 사용한 경우:

1. `certmanager.install`의 값을 `installCertmanager`로 전송합니다.
1. `certmanager.install` 설정을 완전히 제거합니다.

또한 cert-manager 릴리스 정보를 검토하세요:

- [릴리스 정보 1.12 - 1.16](https://cert-manager.io/docs/releases/upgrading/upgrading-1.12/)
- [릴리스 정보 1.17](https://cert-manager.io/docs/releases/upgrading/upgrading-1.16-1.17/)

## GitLab 18.1 {#gitlab-181}

### 파이프라인 작업 제한이 Commits API로 확장됨 {#pipeline-job-limits-extended-to-the-commits-api}

- GitLab 17.7에서 발표
- GitLab 18.1에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/436361)를 참조하세요.

GitLab 18.0부터 활성 파이프라인의 최대 [작업 수](https://docs.gitlab.com/administration/instance_limits/#number-of-jobs-in-active-pipelines)는 [Commits API](https://docs.gitlab.com/api/commits/#set-the-pipeline-status-of-a-commit)를 사용하여 작업을 생성할 때도 적용됩니다. 통합을 검토하여 구성된 작업 제한 내에 있는지 확인합니다.

## GitLab 18.0 {#gitlab-180}

### API Discovery는 기본적으로 브랜치 파이프라인을 사용합니다 {#api-discovery-will-use-branch-pipelines-by-default}

- GitLab 17.9에서 발표됨
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/515487)를 참조하세요.

GitLab 18.0에서 API Discovery용 CI/CD 템플릿(`API-Discovery.gitlab-ci.yml`)의 기본 동작을 업데이트합니다.

GitLab 18.0 이전에 이 템플릿은 MR이 열려 있을 때 기본적으로 [머지 리퀘스트(MR) 파이프라인](https://docs.gitlab.com/ci/pipelines/merge_request_pipelines/)에서 실행되도록 작업을 구성합니다. GitLab 18.0부터 이 템플릿의 동작을 다른 AST 스캐너의 [안정 템플릿 에디션](https://docs.gitlab.com/user/application_security/detect/roll_out_security_scanning/#template-editions) 동작과 정렬합니다:

- 기본적으로 템플릿은 브랜치 파이프라인에서 스캔 작업을 실행합니다.
- CI/CD 변수 `AST_ENABLE_MR_PIPELINES: true`를 설정하여 MR이 열려 있을 때 대신 MR 파이프라인을 사용할 수 있습니다. 이 새 변수의 구현은 [문제 410880](https://gitlab.com/gitlab-org/gitlab/-/issues/410880)에서 추적됩니다.

### 애플리케이션 보안 테스트 분석기 주요 버전 업데이트 {#application-security-testing-analyzers-major-version-update}

- GitLab 17.9에서 발표됨
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/513417)를 참조하세요.

GitLab 18.0에서 모든 애플리케이션 보안 테스트 분석기 컨테이너 이미지의 주요 버전을 업데이트합니다.

기본 포함 템플릿을 사용하지 않거나 분석기 버전을 고정한 경우 CI/CD 작업 정의를 업데이트하여 고정 버전을 제거하거나 최신 주요 버전을 업데이트해야 합니다.

GitLab 17.0부터 GitLab 17.11까지 사용자는 GitLab 18.0 출시까지 분석기 업데이트를 계속 받으며, 그 이후 새로 수정된 버그 및 출시된 기능은 분석기의 새로운 주요 버전에서만 출시됩니다. 그러나 컨테이너 레지스트리에서 게시된 컨테이너 이미지는 제거되지 않습니다.

유지 관리 정책에 따라 더 이상 사용되지 않는 버전의 버그 및 기능을 백포트하지 않습니다. 필요에 따라 최신 3개의 부 릴리스 내에서 보안 패치가 백포트됩니다.

특히 다음 분석기는 GitLab 18.0 출시 후 더 이상 업데이트되지 않습니다:

- GitLab Advanced SAST: 버전 1
- 컨테이너 스캔: 버전 7
- Gemnasium: 버전 5
- DAST: 버전 5
- DAST API: 버전 4
- Fuzz API: 버전 4
- IaC 스캔: 버전 5
- 파이프라인 시크릿 검색: 버전 6
- 정적 애플리케이션 보안 테스트(SAST): [모든 분석기](https://docs.gitlab.com/user/application_security/sast/analyzers/)의 버전 5
  - `kics`
  - `kubesec`
  - `pmd-apex`
  - `semgrep`
  - `sobelow`
  - `spotbugs`

### 예정된 및 시작된 마일스톤 필터의 동작 변경 {#behavior-change-for-upcoming-and-started-milestone-filters}

- GitLab 17.7에서 발표
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/501294)를 참조하세요.

"Upcoming" 및 "Started" 특수 필터의 동작은 향후 GitLab 주요 릴리스 18.0에서 변경될 예정입니다. 두 필터의 새로운 동작은 [문제 429728](https://gitlab.com/gitlab-org/gitlab/-/issues/429728#proposed-issue-filter-logic-for-upcoming-and-started-milestones)에 설명되어 있습니다.

이 변경 사항은 GitLab REST API에 영향을 주지 않으며, 계속해서 기존 마일스톤 필터링 로직을 사용합니다. GitLab GraphQL API는 새로운 필터링 로직을 준수하도록 업데이트됩니다.

### CI/CD 작업 토큰 - **승인된 그룹 및 프로젝트** 허용 목록 강제 {#cicd-job-token---authorized-groups-and-projects-allowlist-enforcement}

- GitLab 16.5에서 발표
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/383084)를 참조하세요.

GitLab 15.9에서 도입된 [**승인된 그룹 및 프로젝트** 설정](https://docs.gitlab.com/ci/jobs/ci_job_token/#add-a-group-or-project-to-the-job-token-allowlist)(GitLab 16.3에서 **이 프로젝트_에_ 대한 액세스 제한**에서 이름이 변경됨)을 사용하면 프로젝트에 대한 CI/CD 작업 토큰 액세스를 제어할 수 있습니다. **이 프로젝트와 허용 목록에 있는 모든 그룹 및 프로젝트만**으로 설정하면 허용 목록에 추가된 그룹 또는 프로젝트만 작업 토큰을 사용하여 프로젝트에 액세스할 수 있습니다.

GitLab 15.9 이전에 생성된 프로젝트의 경우 허용 목록은 기본적으로 비활성화되었으며([**모든 그룹과 프로젝트**](https://docs.gitlab.com/ci/jobs/ci_job_token/#allow-any-project-to-access-your-project) 액세스 설정 선택), 모든 프로젝트의 작업 토큰 액세스를 허용합니다. 허용 목록은 이제 모든 새 프로젝트에서 기본적으로 활성화됩니다. 이전 프로젝트에서는 아직 비활성화되어 있거나 **모든 그룹과 프로젝트** 옵션을 수동으로 선택하여 액세스를 제한 없이 만들었을 수 있습니다.

GitLab 17.6부터 GitLab Self-Managed 및 GitLab Dedicated 인스턴스의 관리자는 선택적으로 [모든 프로젝트에 대해 이 더 안전한 설정을 강제](https://docs.gitlab.com/administration/settings/continuous_integration/#job-token-permissions)할 수 있습니다. 이 설정은 프로젝트 유지 관리자가 **모든 그룹과 프로젝트**를 선택하지 못하도록 합니다. 이 변경 사항은 프로젝트 간의 높은 수준의 보안을 보장합니다.

GitLab 18.0에서 이 인스턴스 설정은 GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 기본적으로 활성화됩니다. GitLab Self-Managed 및 GitLab Dedicated 관리자는 GitLab 18.0으로 업그레이드 후 설정을 비활성화하여 업그레이드 전 동작을 복원할 수 있습니다. GitLab Self-Managed 및 GitLab Dedicated의 경우 GitLab 18.0에서 프로젝트 설정이 변경되지 않지만 인스턴스 설정의 상태는 인스턴스의 모든 프로젝트에 영향을 미칩니다.

이 변경에 대비하기 위해 작업 토큰을 사용하는 프로젝트 유지 관리자는 프로젝트의 **승인된 그룹 및 프로젝트** 허용 목록을 채워야 합니다. 그런 다음 설정을 **이 프로젝트와 허용 목록에 있는 모든 그룹 및 프로젝트만**으로 변경해야 합니다.

CI/CD 작업 토큰으로 프로젝트에 인증하는 프로젝트를 식별하기 위해 GitLab 17.6에서 [작업 토큰 인증을 추적](https://docs.gitlab.com/releases/17/gitlab-17-6-released/#track-cicd-job-token-authentications)하는 방법도 도입했습니다. 해당 데이터를 사용하여 CI/CI 작업 토큰 허용 목록을 채울 수 있습니다.

GitLab 17.10부터 18.6까지 [마이그레이션 도구](https://archives.docs.gitlab.com/18.6/ci/jobs/ci_job_token/#auto-populate-a-projects-allowlist)를 사용하여 작업 토큰 인증 로그에서 CI/CD 작업 토큰 허용 목록을 자동으로 채울 수 있습니다. [GitLab 18.0의 일반 허용 목록 강제](https://docs.gitlab.com/update/deprecations/?removal_milestone=18.0#cicd-job-token-authorized-groups-and-projects-allowlist-enforcement) 이전에 이 마이그레이션 도구를 사용하여 허용 목록을 채우고 사용하도록 권장합니다. GitLab 18.0에서 허용 목록의 자동 채우기 및 강제는 이전에 발표한 대로 GitLab.com에서 발생합니다.

이 마이그레이션 도구는 GitLab 18.7에서 [제거](https://gitlab.com/gitlab-org/gitlab/-/work_items/498305)되었습니다.

### CI/CD 작업 토큰 - **프로젝트에서 액세스 제한** 설정 제거 {#cicd-job-token---limit-access-from-your-project-setting-removal}

- GitLab 15.9에서 발표
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/395708)를 참조하세요.

GitLab 14.4에서 더 안전하게 하기 위해 [프로젝트의 CI/CD 작업 토큰(`CI_JOB_TOKEN`)_에서_ 액세스를 제한](https://docs.gitlab.com/ci/jobs/ci_job_token/#limit-your-projects-job-token-access)하는 설정을 도입했습니다. 이 설정을 **CI_JOB_TOKEN 액세스 제한**이라고 합니다. GitLab 16.3에서 명확성을 위해 이 설정을 **이 프로젝트_에서_ 액세스 제한**으로 이름을 바꿨습니다.

GitLab 15.9에서 [**승인된 그룹 및 프로젝트**](https://docs.gitlab.com/ci/jobs/ci_job_token/#add-a-group-or-project-to-the-job-token-allowlist)라는 대체 설정을 도입했습니다. 이 설정은 허용 목록을 사용하여 프로젝트_에_ 대한 작업 토큰 액세스를 제어합니다. 이 새로운 설정은 원래보다 훨씬 향상되었습니다. 첫 번째 반복은 GitLab 16.0에서 더 이상 사용되지 않으며 GitLab 18.0에서 제거될 예정입니다.

**이 프로젝트_에서_ 액세스 제한** 설정은 모든 새 프로젝트에서 기본적으로 비활성화됩니다. GitLab 16.0 이상에서는 프로젝트에서 비활성화된 후 이 설정을 다시 활성화할 수 없습니다. 대신 **승인된 그룹 및 프로젝트** 설정을 사용하여 프로젝트에 대한 작업 토큰 액세스를 제어합니다.

### DAST `dast_crawl_extract_element_timeout` 및 `dast_crawl_search_element_timeout` 변수 {#dast-dast_crawl_extract_element_timeout-and-dast_crawl_search_element_timeout-variables}

- GitLab 17.9에서 발표됨
- GitLab 18.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/517250)를 참조하세요.

DAST 변수 `DAST_CRAWL_EXTRACT_ELEMENT_TIMEOUT` 및 `DAST_CRAWL_SEARCH_ELEMENT_TIMEOUT`는 더 이상 사용되지 않으며 GitLab 18.0에서 제거될 예정입니다. 도입되었을 때 변수는 특정 브라우저 상호 작용에 대한 세분화된 타임아웃 제어를 제공했습니다. 이러한 상호 작용은 이제 공통 타임아웃 값으로 관리되며, 이는 변수를 불필요하게 만듭니다. 또한 기본 구현 문제로 인해 DAST 브라우저 기반 분석기가 도입된 이후로 변수가 작동하지 않았습니다. 이 두 변수를 제거하면 DAST 구성이 단순화되고 사용자를 위한 더 나은 온보딩 경험을 제공합니다.

### DAST `dast_devtools_api_timeout`은(는) 더 낮은 기본값을 갖습니다 {#dast-dast_devtools_api_timeout-will-have-a-lower-default-value}

- GitLab 17.9에서 발표됨
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/517254)를 참조하세요.

`DAST_DEVTOOLS_API_TIMEOUT` 환경 변수는 DAST 스캔이 브라우저의 응답을 기다리는 시간을 결정합니다. GitLab 18.0 이전에 변수는 45초의 정적 값을 가집니다. GitLab 18.0 이후 `DAST_DEVTOOLS_API_TIMEOUT` 환경 변수는 다른 타임아웃 구성을 기반으로 계산되는 동적 값을 가집니다. 대부분의 경우 45초 값은 많은 스캐너 함수의 타임아웃 값보다 높았습니다. 동적으로 계산된 값은 `DAST_DEVTOOLS_API_TIMEOUT` 변수가 적용되는 경우의 수를 증가시켜 변수를 더 유용하게 만듭니다.

잠재적인 중단을 줄이기 위해 다음 일정에 따라 기본 타임아웃 값을 점진적으로 조정합니다:

| 타임아웃 값 | 마일스톤         |
|:--------------|:------------------|
| 45            | 17.11 이전 |
| 30            | 18.0              |
| 20            | 18.1              |
| 10            | 18.2              |
| 5             | 18.3              |

### 종속성 프록시 토큰 범위 강제 {#dependency-proxy-token-scope-enforcement}

- GitLab 17.9에서 발표됨
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/426887)를 참조하세요.

컨테이너용 종속성 프록시는 범위 검증 없이 개인 액세스 토큰 또는 그룹 액세스 토큰을 사용하는 `docker login` 및 `docker pull` 요청을 허용합니다.

GitLab 18.0에서 종속성 프록시는 인증을 위해 `read_registry` 및 `write_registry` 범위를 모두 요구합니다. 이 변경 후 이러한 범위가 없는 토큰을 사용한 인증 시도는 거부됩니다.

이것은 주요 변경입니다. 업그레이드 전에 [필요한 범위](https://docs.gitlab.com/user/packages/dependency_proxy/#authenticate-with-the-dependency-proxy-for-container-images)로 새 액세스 토큰을 생성하고 워크플로 변수 및 스크립트를 이러한 새 토큰으로 업데이트합니다.

이 변경이 GitLab Self-Managed 인스턴스에 미치는 영향을 평가하기 위해 GitLab 17.10 이상에서 인증 로그를 모니터링하여 경고 메시지를 확인할 수 있습니다. `auth_json.log` 파일에서 `Dependency proxy missing authentication abilities`를 포함하는 항목을 찾습니다. GitLab Helm chart 또는 GitLab Dedicated를 사용 중인 경우 로그는 `component: "gitlab"` 및 `subcomponent: "auth_json"`에 있습니다. 이러한 항목은 필요한 범위 없는 토큰을 사용한 인증 시도를 표시하며, GitLab 18.0으로 업그레이드한 후 실패합니다.

### Terraform CI/CD 템플릿 더 이상 사용 안 됨 {#deprecate-terraform-cicd-templates}

- GitLab 16.9에서 발표
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/438010)를 참조하세요.

Terraform CI/CD 템플릿은 더 이상 사용되지 않으며 GitLab 18.0에서 제거될 예정입니다. 이는 다음 템플릿에 영향을 미칩니다:

- `Terraform.gitlab-ci.yml`
- `Terraform.latest.gitlab-ci.yml`
- `Terraform/Base.gitlab-ci.yml`
- `Terraform/Base.latest.gitlab-ci.yml`

GitLab 16.9에서 사용자에게 사용 중단을 알리기 위해 새 작업이 템플릿에 추가됩니다. 경고는 영향을 받는 파이프라인의 `deprecated-and-will-be-removed-in-18.0` 작업을 자리 표시자 작업으로 덮어써서 끌 수 있습니다.

GitLab은 작업 이미지의 `terraform` 바이너리를 BSL로 라이선스된 버전으로 업데이트할 수 없습니다.

Terraform을 계속 사용하려면 템플릿 및 [Terraform 이미지](https://gitlab.com/gitlab-org/terraform-images)를 복제하고 필요에 따라 유지 관리합니다. GitLab은 [사용자 정의 빌드 이미지로 마이그레이션하기 위한 자세한 지침](https://gitlab.com/gitlab-org/terraform-images)을 제공합니다.

대신 GitLab.com의 새 OpenTofu CI/CD 구성 요소 또는 GitLab Self-Managed의 새 OpenTofu CI/CD 템플릿을 사용하도록 권장합니다. CI/CD 구성 요소는 아직 GitLab Self-Managed에서 사용할 수 없지만 [문제 #415638](https://gitlab.com/gitlab-org/gitlab/-/issues/415638)은 이 기능을 추가할 것을 제안합니다. CI/CD 구성 요소가 GitLab Self-Managed에서 사용 가능하면 OpenTofu CI/CD 템플릿이 제거됩니다.

[새 OpenTofu CI/CD 구성 요소](https://gitlab.com/components/opentofu)에 대해 자세히 알아봅니다.

### 라이선스 메타데이터 형식 V1 더 이상 사용 안 됨 {#deprecate-license-metadata-format-v1}

- GitLab 16.9에서 발표
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/438477)를 참조하세요.

라이선스 메타데이터 형식 V1 데이터 세트는 더 이상 사용되지 않으며 GitLab 18.0에서 제거될 예정입니다.

`package_metadata_synchronization` 기능 플래그가 활성화된 사용자는 GitLab 16.3 이상으로 업그레이드하고 기능 플래그 구성을 제거하도록 권장됩니다.

### `STORAGE` 열거형을 `NamespaceProjectSortEnum` GraphQL API에서 사용 중단 {#deprecation-of-storage-enum-in-namespaceprojectsortenum-graphql-api}

- GitLab 17.7에서 발표
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/396284)를 참조하세요.

GitLab GraphQL API의 `NamespaceProjectSortEnum`의 `STORAGE` 열거형은 GitLab 18.0에서 제거될 예정입니다.

이 변경에 준비하기 위해 `NamespaceProjectSortEnum`과 상호 작용하는 GraphQL 쿼리를 검토하고 업데이트하도록 권장합니다. `STORAGE` 필드에 대한 모든 참조를 `EXCESS_REPO_STORAGE_SIZE_DESC`으로 바꿉니다.

### `name` 필드를 `ProjectMonthlyUsageType` GraphQL API에서 사용 중단 {#deprecation-of-name-field-in-projectmonthlyusagetype-graphql-api}

- GitLab 17.7에서 발표
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/381894)를 참조하세요.

GitLab GraphQL API의 `ProjectMonthlyUsageType`의 `name` 필드는 GitLab 18.0에서 제거될 예정입니다.

이 변경에 준비하기 위해 `ProjectMonthlyUsageType`과 상호 작용하는 GraphQL 쿼리를 검토하고 업데이트하도록 권장합니다. `name` 필드에 대한 모든 참조를 `project.name`으로 바꿉니다.

### GitLab NGINX chart 컨트롤러 이미지 v1.3.1에 대한 폴백 지원 {#fallback-support-for-gitlab-nginx-chart-controller-image-v131}

- GitLab 17.6에서 발표
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/5794)를 참조하세요.

> [!note]
> 이 변경 사항은 [GitLab NGINX chart](https://docs.gitlab.com/charts/charts/nginx/)를 사용 중이고 자신의 NGINX RBAC 규칙을 설정한 경우에만 영향을 미칩니다.
>
> 자신의 [외부 NGINX chart](https://docs.gitlab.com/charts/advanced/external-nginx/)를 사용 중이거나 NGINX RBAC 규칙 변경 없이 GitLab NGINX chart를 사용 중인 경우 이 사용 중단이 적용되지 않습니다.

GitLab 17.6(Helm chart 8.6)에서 GitLab chart는 기본 NGINX 컨트롤러 이미지를 버전 1.3.1에서 1.11.2로 업데이트했습니다. 이 새 버전에는 GitLab NGINX chart에 추가된 새 RBAC 규칙이 필요하므로 궁극적으로 이러한 규칙을 생성해야 합니다. 이 변경 사항은 다음으로도 백포트됩니다:

- GitLab 17.5.1(Helm chart 8.5.1)
- GitLab 17.4.3(Helm chart 8.4.3)
- GitLab 17.3.6(Helm chart 8.3.6)

> [!note]
> Helm chart 8.3에서 8.7까지의 최신 패치 버전에는 NGINX 컨트롤러 버전 1.11.2가 포함되어 있습니다. 이후 chart 버전에는 다양한 보안 수정 사항이 포함되어 있으므로 버전 1.11.5가 포함되어 있습니다. GitLab 18.0은 컨트롤러 버전 1.11.5를 기본값으로 지정합니다.

자신의 NGINX RBAC 규칙을 관리하는 경우 `nginx-ingress.rbac.create`를 `false`로 설정했다는 의미입니다. 이 경우 GitLab 17.3(Helm chart 8.3)부터 GitLab 17.11(Helm chart 8.11)까지 해당 변경을 감지하고 이전 컨트롤러 이미지를 사용하는 폴백 메커니즘이 있으므로 RBAC 규칙을 변경할 필요가 없습니다.

GitLab 18.0(Helm chart 9.0)부터 이 폴백 메커니즘이 제거되므로 새 컨트롤러 이미지가 사용되고 새 RBAC 규칙이 있어야 합니다.

GitLab 18.0에서 강제되기 전에 새 NGINX 컨트롤러 이미지를 활용하려면:

1. 클러스터에 새 RBAC 규칙을 추가하세요 [예시 참조](https://gitlab.com/gitlab-org/charts/gitlab/-/merge_requests/3901/diffs?commit_id=93a3cbdb5ad83db95e12fa6c2145df0800493d8b).
1. `nginx-ingress.controller.image.disableFallback`을 `true`로 설정합니다.

자세한 내용은 [chart 릴리스 페이지](https://docs.gitlab.com/charts/releases/8_0/#upgrade-to-86x-851-843-836)를 참조하세요.

### Gitaly 속도 제한 {#gitaly-rate-limiting}

- GitLab 17.7에서 발표
- GitLab 18.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitaly/-/issues/5011)를 참조하세요.

Git 작업 및 리포지토리 지연의 매우 가변적인 특성으로 인해 Gitaly [RPC 기반 속도 제한](https://docs.gitlab.com/administration/gitaly/monitoring/#monitor-gitaly-rate-limiting)은 효과가 없습니다. 적절한 속도 제한을 구성하는 것은 어려우며 해로운 작업이 초당 충분한 요청을 생성하지 않아 두드러질 가능성이 낮기 때문에 종종 빠르게 구식이 됩니다.

Gitaly는 이미 [동시성 제한](https://docs.gitlab.com/administration/gitaly/concurrency_limiting/) 및 [적응형 제한 추가 기능](https://docs.gitlab.com/administration/gitaly/concurrency_limiting/#adaptive-concurrency-limiting)을 지원하며, 이는 프로덕션에서 잘 작동하는 것으로 입증되었습니다.

Gitaly가 외부 네트워크에 직접 노출되지 않고 로드 밸런서와 같은 외부 보호 계층이 더 나은 보안을 제공하기 때문에 속도 제한이 덜 효과적입니다.

따라서 더 안정적인 동시성 제한을 위해 속도 제한을 더 이상 사용하지 않습니다. Gitaly RPC 기반 속도 제한은 GitLab 18.0에서 제거될 예정입니다.

### 레거시 Web IDE는 더 이상 사용되지 않습니다 {#legacy-web-ide-is-deprecated}

- GitLab 17.9에서 발표됨
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/513938)를 참조하세요.

레거시 Vue 기반 GitLab Web IDE 구현이 GitLab에서 제거될 예정입니다. 이 변경은 GitLab VSCode Fork 기반 Web IDE로의 성공적인 전환을 따릅니다. 이는 GitLab 15.11 이후 기본 Web IDE 경험이었습니다.

이 제거는 여전히 레거시 Web IDE 구현에 액세스 중인 사용자에게 영향을 미칩니다.

이 제거에 준비하기 위해 GitLab 인스턴스에서 이전에 비활성화된 경우 `vscode_web_ide` 기능 플래그를 활성화합니다.

### 정책당 허용된 스캔 실행 정책 작업의 수 제한 {#limit-number-of-scan-execution-policy-actions-allowed-per-policy}

- GitLab 17.5에서 발표됨
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/510897)를 참조하세요.

정책당 허용되는 최대 스캔 실행 정책 작업에 대한 새로운 제한이 추가되었습니다. 이 변경은 기능 플래그 `scan_execution_policy_action_limit` 및 `scan_execution_policy_action_limit_group` 뒤에 17.4에 도입되었습니다. 활성화되면 스캔 실행 정책의 처음 10개 작업만 처리됩니다.

제한을 추가하면 보안 정책의 성능 및 확장성을 보장할 수 있습니다.

추가 작업이 필요한 경우 기존 정책을 10개 이하의 작업으로 제한합니다. 그런 다음 추가 작업이 있는 새로운 스캔 실행 정책을 생성합니다. 보안 정책 프로젝트당 5개의 스캔 실행 정책 한계 내에서 생성합니다.

GitLab Self-Managed 및 GitLab Dedicated 관리자는 `scan_execution_policies_action_limit` 애플리케이션 설정으로 사용자 정의 제한을 구성할 수 있습니다.

### 스캔 실행 정책에서 제한된 `scan` 작업 {#limited-scan-actions-in-a-scan-execution-policy}

- GitLab 17.5에서 발표됨
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/472213)를 참조하세요.

GitLab.com에서 GitLab 18.0부터 [스캔 실행 정책](https://docs.gitlab.com/user/application_security/policies/scan_execution_policies/)은 정책당 10개의 `scan` 작업으로 제한됩니다. 제한을 초과하는 새 정책을 만들 수 없으며 제한을 초과하는 기존 정책을 업데이트할 수 없습니다. 제한을 초과하는 기존 정책의 경우 정책의 처음 10개 `scan` 작업만 실행됩니다.

GitLab Self-Managed 및 GitLab Dedicated 인스턴스에서 `scan_execution_policies_action_limit` 애플리케이션 설정으로 사용자 정의 제한을 구성할 수 있습니다. 이러한 인스턴스의 제한은 0개 작업으로 기본값을 지정합니다. 10개 작업의 제한을 구성하도록 권장합니다.

### Prometheus 하위 chart의 주요 업데이트 {#major-update-of-the-prometheus-subchart}

- GitLab 17.9에서 발표됨
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/5927)를 참조하세요.

GitLab 18.0 및 GitLab chart 9.0을 사용하면 Prometheus 하위 chart가 15.3에서 27.3으로 업데이트됩니다. 이 업데이트와 함께 Prometheus 3이 기본적으로 제공됩니다.

업그레이드를 수행하려면 수동 단계가 필요합니다. Alertmanager, Node Exporter 또는 Pushgateway를 활성화한 경우 Helm 값도 업데이트해야 합니다.

자세한 내용은 [마이그레이션 가이드](https://docs.gitlab.com/charts/releases/9_0/#prometheus-upgrade)를 참조하세요.

### GitLab.com의 취약성에 대한 새로운 데이터 보존 제한 {#new-data-retention-limits-for-vulnerabilities-on-gitlabcom}

- GitLab 17.9에서 발표됨
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/groups/gitlab-org/-/epics/16629)를 참조하세요.

GitLab 18.0에서 GitLab.com Ultimate 고객을 위해 시스템 성능 및 안정성을 향상시키기 위해 새로운 데이터 보존 제한을 도입합니다. 데이터 보존 제한은 취약성 데이터가 저장되는 기간에 영향을 미칩니다. 12개월보다 오래되고 업데이트되지 않은 취약성은 자동으로 콜드 스토리지 아카이브로 이동됩니다. 이러한 아카이브는:

- GitLab UI를 통해 액세스 가능하고 다운로드 가능합니다.
- 3년 동안 보유됩니다.
- 3년 후 영구 삭제됩니다.

### PostgreSQL 14 및 15는 더 이상 지원되지 않습니다 {#postgresql-14-and-15-no-longer-supported}

- GitLab 17.9에서 발표됨
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/521663)를 참조하세요.

GitLab은 PostgreSQL에 대해 [연간 업그레이드 주기](https://handbook.gitlab.com/handbook/engineering/data-engineering/database-excellence/database-frameworks/postgresql-upgrade-cadence/)를 따릅니다.

PostgreSQL 14 및 15에 대한 지원은 GitLab 18.0에서 제거될 예정입니다. GitLab 18.0에서 PostgreSQL 16이 필요한 최소 PostgreSQL 버전이 됩니다.

PostgreSQL 14 및 15는 전체 GitLab 17 릴리스 사이클 동안 지원될 예정입니다. PostgreSQL 16도 GitLab 18.0 이전에 업그레이드하려는 인스턴스에서 지원될 예정입니다.

단일 PostgreSQL 인스턴스를 Omnibus Linux 패키지를 사용하여 설치한 경우 17.11과 자동 업그레이드가 시도될 수 있습니다. 업그레이드를 수용할 충분한 디스크 공간이 있는지 확인하세요. 자세한 내용은 [Omnibus 데이터베이스 설명서](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server)를 참조하세요.

### 그룹 설정의 프로젝트 페이지가 더 이상 사용되지 않음 {#project-page-in-group-settings-is-deprecated}

- GitLab 17.0에서 발표
- GitLab 17.9에서 지원 종료
- GitLab 18.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/443347)를 참조하세요.

그룹 소유자는 그룹이 포함하는 프로젝트를 나열하는 그룹 설정의 프로젝트 페이지에 액세스할 수 있으며, 각 프로젝트의 프로젝트를 만들거나 편집하거나 삭제하는 옵션과 구성원 페이지 링크가 있습니다. 이 모든 기능은 그룹 개요 페이지 및 프로젝트의 각 구성원 페이지에서 사용할 수 있습니다. 그룹 설정의 프로젝트 페이지 사용량이 적고 접근성이 제한되어 있어 이 페이지는 더 이상 사용되지 않을 예정입니다. 이 변경은 사용자 인터페이스에만 영향을 미칩니다. 기본 API는 계속 사용 가능하므로 [Projects API](https://docs.gitlab.com/api/projects/)를 사용하여 프로젝트 생성, 편집 및 삭제를 계속 수행할 수 있습니다. 17.9에서 이 페이지에서 그룹 개요 페이지로 리디렉션을 구현합니다. 프로젝트 페이지는 18.0의 그룹 설정에서 완전히 제거됩니다.

### REST API 끝점 `pre_receive_secret_detection_enabled`은(는) 더 이상 사용되지 않습니다 {#rest-api-endpoint-pre_receive_secret_detection_enabled-is-deprecated}

- GitLab 17.9에서 발표됨
- GitLab 18.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/514413)를 참조하세요.

REST API 끝점 `pre_receive_secret_detection_enabled`은(는) `secret_push_protection_enabled`를 위해 더 이상 사용되지 않습니다. 기능 `pre_receive_secret_detection`를 `secret_push_protection`로 이름을 변경한 것을 반영하기 위해 일부 API 필드의 이름을 바꾸고 있습니다.

새 API 필드 이름을 추가했지만 원래 발표한 대로 GitLab 18.0에서 이전 필드 이름을 제거하지 않을 예정입니다.

데이터베이스를 업데이트하여 이전 `pre_receive_secret_detection_enabled` 데이터베이스 열을 [제거](https://gitlab.com/gitlab-org/gitlab/-/issues/512996)하지만 API 필드 이름 중 하나를 사용할 수 있습니다. 둘 다 새로운 `secret_push_protection_enabled` 데이터베이스 열의 값을 반영합니다.

### Raspberry Pi 32비트 패키지는 더 이상 사용되지 않습니다 {#raspberry-pi-32-bit-packages-are-deprecated}

- GitLab 17.9에서 발표됨
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/519113)를 참조하세요.

GitLab 버전 18.0부터 Raspberry Pi용 32비트 패키지를 더 이상 제공하지 않습니다. 64비트 Raspberry Pi OS를 사용하고 [`arm64` Debian 패키지를 설치](https://about.gitlab.com/install/#debian)해야 합니다. 32비트 OS에서 데이터를 백업하고 64비트 OS로 복원하는 방법에 대한 자세한 내용은 [PostgreSQL용 운영 체제 업그레이드](https://docs.gitlab.com/administration/postgresql/upgrading_os/)를 참조하세요.

### `allowed_pull_policies`에 없는 컨테이너 이미지 풀 정책 거부 {#reject-container-image-pull-policies-not-in-allowed_pull_policies}

- GitLab 17.9에서 발표됨
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/516107)를 참조하세요.

구성된 모든 풀-정책은 runner의 `config.toml` 파일에 지정된 [`allowed_pull_policies` 구성](https://docs.gitlab.com/runner/executors/docker/#allow-docker-pull-policies)에 있어야 합니다. 없으면 작업이 `incompatible pull policy` 오류와 함께 실패해야 합니다.

현재 구현에서 여러 풀 정책이 정의되면 `allowed-pull-policies`의 정책 중 적어도 하나가 일치하면 작업이 통과합니다. 다른 정책이 포함되지 않은 경우에도 마찬가지입니다.

GitLab 18.0에서 `allowed-pull-policies`의 정책과 일치하지 않는 경우에만 작업이 실패합니다. 그러나 현재 동작과 달리 작업은 `allowed-pull-policies`에 나열된 풀 정책만 사용합니다. 이 구별은 현재 통과하는 작업이 GitLab 18.0에서 실패하게 할 수 있습니다.

### duoProAssignedUsersCount GraphQL 필드 제거 {#remove-duoproassigneduserscount-graphql-field}

- GitLab 17.9에서 발표됨
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/498671)를 참조하세요.

18.0에서 `duoProAssignedUsersCount` GraphQL 필드를 제거 중입니다. 사용자가 [`aiMetrics` API](https://docs.gitlab.com/api/graphql/reference/objects/#aimetrics)에서 이 필드를 사용하는 중인 경우 문제가 발생할 수 있으며 대신 `duoAssignedUsersCount`를 사용할 수 있습니다. 이 제거는 [GitLab Duo Pro 및 Duo 사용자가 할당한 사용자를 모두 계산하기 위한 수정](https://gitlab.com/gitlab-org/gitlab/-/issues/485510)의 일부입니다.

### `setPreReceiveSecretDetection` GraphQL 변형을 `setSecretPushProtection`로 이름 바꾸기 {#rename-setprereceivesecretdetection-graphql-mutation-to-setsecretpushprotection}

- GitLab 17.7에서 발표
- GitLab 18.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/514414)를 참조하세요.

`setPreReceiveSecretDetection` GraphQL 변형은 `setSecretPushProtection`로 이름이 변경되었습니다. 또한 기능 `pre_receive_secret_detection`를 `secret_push_protection`로 이름을 변경한 것을 반영하기 위해 변형 응답의 일부 필드의 이름도 바꾸고 있습니다.

새 변형 이름을 추가했지만 원래 발표한 대로 GitLab 18.0에서 이전 변형 이름을 제거하지 않을 예정입니다.

데이터베이스를 업데이트하여 이전 `pre_receive_secret_detection_enabled` 데이터베이스 열을 [제거](https://gitlab.com/gitlab-org/gitlab/-/issues/512996)하지만 변형 이름 중 하나를 사용할 수 있습니다. 둘 다 새로운 `secret_push_protection_enabled` 데이터베이스 열의 값을 반영합니다.

### GitGuardian 시크릿 검색을 건너뛰기 위한 옵션 이름 바꾸기 {#rename-options-to-skip-gitguardian-secret-detection}

- GitLab 17.3에서 발표됨
- GitLab 18.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/470119)를 참조하세요.

GitGuardian 시크릿 검색을 건너뛰기 위한 옵션 `[skip secret detection]` 및 `secret_detection.skip_all`는 더 이상 사용되지 않습니다. 대신 `[skip secret push protection]` 및 `secret_push_protection.skip_all`를 사용해야 합니다.

새 단어를 사용하도록 권장하지만 GitLab 18.0에서 이전 옵션을 제거하지 않을 예정입니다.

### `add_on_purchase` GraphQL 필드를 `add_on_purchases`로 바꾸기 {#replace-add_on_purchase-graphql-field-with-add_on_purchases}

- GitLab 17.4에서 발표됨
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/476858)를 참조하세요.

GraphQL 필드 `add_on_purchase`은(는) GitLab 17.4에서 더 이상 사용되지 않으며 GitLab 18.0에서 제거될 예정입니다. `add_on_purchases` 필드를 대신 사용하세요.

### 네임스페이스 `add_on_purchase` GraphQL 필드를 `add_on_purchases`로 바꾸기 {#replace-namespace-add_on_purchase-graphql-field-with-add_on_purchases}

- GitLab 17.5에서 발표됨
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/489850)를 참조하세요.

네임스페이스 GraphQL 필드 `add_on_purchase`은(는) GitLab 17.5에서 더 이상 사용되지 않으며 GitLab 18.0에서 제거될 예정입니다. 대신 루트 `add_on_purchases` 필드를 사용합니다.

### SUSE Linux Enterprise Server 15 SP2에 대한 지원 {#support-for-suse-linux-enterprise-server-15-sp2}

- GitLab 17.9에서 발표됨
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8888)를 참조하세요.

SUSE Linux Enterprise Server(SLES) 15 SP2의 장기 서비스 및 지원(LTSS)은 2024년 12월에 종료되었습니다.

따라서 더 이상 Linux 패키지 설치를 위해 SLES SP2 배포를 지원하지 않습니다. 계속 지원을 받으려면 SLES 15 SP6으로 업그레이드해야 합니다.

### `direction` GraphQL 인수 `ciJobTokenScopeRemoveProject`는 더 이상 사용되지 않음 {#the-direction-graphql-argument-for-cijobtokenscoperemoveproject-is-deprecated}

- GitLab 16.9에서 발표
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/383084)를 참조하세요.

`direction` GraphQL 인수 `ciJobTokenScopeRemoveProject` 변형은 더 이상 사용되지 않습니다. GitLab 15.9에서 발표한 [기본 CI/CD 작업 토큰 범위 변경](https://docs.gitlab.com/update/deprecations/#default-cicd-job-token-ci_job_token-scope-changed)에 따라 `direction` 인수는 `INBOUND`로 기본값을 지정하며 `OUTBOUND`은(는) GitLab 17.0에서 더 이상 유효하지 않습니다. GitLab 18.0에서 `direction` 인수를 제거합니다.

`OUTBOUND` 인수를 사용하여 `direction`를 사용하여 프로젝트의 토큰 액세스 방향을 제어하는 경우 작업 토큰을 사용하는 파이프라인이 인증 실패할 수 있습니다. 파이프라인이 예상대로 계속 실행되도록 하려면 명시적으로 [프로젝트의 허용 목록에 다른 프로젝트를 추가](https://docs.gitlab.com/ci/jobs/ci_job_token/#add-a-group-or-project-to-the-job-token-allowlist)해야 합니다.

### API에서 메모 기밀성을 전환 {#toggle-notes-confidentiality-on-apis}

- GitLab 14.10에서 발표
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/350670)를 참조하세요.

REST 및 GraphQL API를 사용하여 메모 기밀성을 전환하는 것은 더 이상 사용되지 않습니다. 메모 기밀 속성 업데이트는 더 이상 어떤 수단으로도 지원되지 않습니다. 우리는 경험을 단순화하고 개인 정보가 의도치 않게 노출되는 것을 방지하기 위해 이를 변경하고 있습니다.

### Gitaly 저장소 구성을 위한 `git_data_dirs` {#git_data_dirs-for-configuring-gitaly-storages}

- GitLab 16.0에서 발표
- GitLab 18.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8786)를 참조하세요.

Linux 패키지 인스턴스에 대해 Gitaly 저장소를 구성하기 위해 `git_data_dirs`을(를) 사용하기 위한 지원은 [16.0 이후](https://docs.gitlab.com/update/versions/gitlab_16_changes/#gitaly-configuration-structure-change) 더 이상 사용되지 않으며 18.0에서 제거될 예정입니다.

마이그레이션 지침은 [`git_data_dirs`에서 마이그레이션](https://docs.gitlab.com/omnibus/settings/configuration/#migrating-from-git_data_dirs)을 참조하세요.

## GitLab 17.11 {#gitlab-1711}

### 클라이언트 자격 증명 없이 OAuth ROPC 부여가 더 이상 사용되지 않음 {#oauth-ropc-grant-without-client-credentials-is-deprecated}

- GitLab 17.11에서 발표
- GitLab 17.11에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/535298)를 참조하세요.

GitLab.com은 2025년 4월 8일부터 OAuth Resource Owner Password Credentials(ROPC) OAuth 부여에 대한 클라이언트 인증이 필요합니다. ROPC는 RFC 버전 2.1에서 OAuth 작업 그룹이 생략했습니다. 클라이언트 자격 증명 없는 기존 ROPC 통합은 이 날짜 이후 서비스 중단을 경험할 것입니다. 서비스 중단이 발생하면 마감일 전에 클라이언트 자격 증명을 포함하도록 통합을 업데이트합니다. 자세한 내용은 [블로그](https://about.gitlab.com/blog/improving-oauth-ropc-security-on-gitlab-com/)에서 확인할 수 있습니다.

## GitLab 17.9 {#gitlab-179}

### openSUSE Leap 15.5에 대한 지원 {#support-for-opensuse-leap-155}

- GitLab 17.6에서 발표
- GitLab 17.9에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8778)를 참조하세요.

[openSUSE Leap에 대한 장기 서비스 및 지원(LTSS)은 2024년 12월에 종료](https://en.opensuse.org/Lifetime#openSUSE_Leap)됩니다.

따라서 더 이상 Linux 패키지 설치를 위해 openSUSE Leap 15.5 배포를 지원하지 않습니다. 사용자는 계속 지원을 받기 위해 openSUSE Leap 15.6으로 업그레이드해야 합니다.

## GitLab 17.8 {#gitlab-178}

### CentOS 7에 대한 지원 {#support-for-centos-7}

- GitLab 17.6에서 발표
- GitLab 17.8에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8714)를 참조하세요.

[CentOS 7의 장기 서비스 및 지원(LTSS)은 2024년 6월에 종료](https://www.redhat.com/en/topics/linux/centos-linux-eol)되었습니다.

따라서 더 이상 Linux 패키지 설치를 위해 CentOS 7 배포를 지원하지 않습니다. 사용자는 계속 지원을 받기 위해 다른 운영 체제로 업그레이드해야 합니다.

### Oracle Linux 7에 대한 지원 {#support-for-oracle-linux-7}

- GitLab 17.6에서 발표
- GitLab 17.8에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8746)를 참조하세요.

[Oracle Linux 7의 장기 서비스 및 지원(LTSS)은 2024년 12월에 종료](https://wiki.debian.org/LTS)됩니다.

따라서 더 이상 Linux 패키지 설치를 위해 Oracle Linux 7 배포를 지원하지 않습니다. 사용자는 계속 지원을 받기 위해 Oracle Linux 8로 업그레이드해야 합니다.

### Raspberry Pi OS Buster에 대한 지원 {#support-for-raspberry-pi-os-buster}

- GitLab 17.6에서 발표
- GitLab 17.8에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8734)를 참조하세요.

Raspberry Pi OS Buster(이전의 Raspbian Buster)의 장기 서비스 및 지원(LTSS)은 2024년 6월에 종료되었습니다.

따라서 더 이상 Linux 패키지 설치를 위해 PiOS Buster 배포를 지원하지 않습니다. 사용자는 계속 지원을 받기 위해 PiOS Bullseye로 업그레이드해야 합니다.

### Red Hat Enterprise Linux 7에 대한 지원 {#support-for-red-hat-enterprise-linux-7}

- GitLab 17.6에서 발표
- GitLab 17.8에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8714)를 참조하세요.

Red Hat Enterprise Linux(RHEL) 7이 [2024년 6월 유지 관리 지원 종료](https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux/rhel-7-end-of-maintenance)에 도달했습니다.

따라서 더 이상 RHEL 7 및 RHEL 7 호환 운영 체제에 대한 Linux 패키지를 게시하지 않습니다. 사용자는 계속 지원을 받기 위해 RHEL 8로 업그레이드해야 합니다.

### Scientific Linux 7에 대한 지원 {#support-for-scientific-linux-7}

- GitLab 17.6에서 발표
- GitLab 17.8에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8745)를 참조하세요.

[Scientific Linux 7의 장기 서비스 및 지원(LTSS)은 2024년 6월에 종료](https://scientificlinux.org/downloads/sl-versions/sl7/)되었습니다.

따라서 더 이상 Linux 패키지 설치를 위해 Scientific Linux 배포를 지원하지 않습니다. 사용자는 다른 RHEL 호환 운영 체제로 업그레이드해야 합니다.

## GitLab 17.7 {#gitlab-177}

### `/repository/tree` REST API 끝점의 오류 처리가 `404`를 반환합니다 {#error-handling-for-repositorytree-rest-api-endpoint-returns-404}

- GitLab 16.5에서 발표
- GitLab 17.7에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/420865)를 참조하세요.

GitLab 17.7에서 요청된 경로를 찾을 수 없을 때 리스트 리포지토리 트리 API 끝점 `/projects/:id/repository/tree`의 오류 처리 동작이 업데이트됩니다. 끝점은 이제 상태 코드 `404 Not Found`를 반환합니다. 이전에 상태 코드는 `200 OK`였습니다.

이 변경은 GitLab 16.5의 GitLab.com에서 활성화되었으며 GitLab 17.7의 자체 관리 인스턴스에서 사용 가능할 예정입니다.

구현이 누락된 경로에 대해 빈 배열이 있는 `200` 상태 코드를 받는 데 의존하는 경우 새로운 `404` 응답을 처리하기 위해 오류 처리를 업데이트해야 합니다.

### TLS 1.0 및 1.1은 더 이상 지원되지 않습니다 {#tls-10-and-11-no-longer-supported}

- GitLab 17.4에서 발표됨
- GitLab 17.7에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/164512)를 참조하세요.

[OpenSSL 버전 1.1.1의 장기 지원은 2023년 9월에 종료되었습니다](https://endoflife.date/openssl). 따라서 OpenSSL 3이 GitLab 17.7의 기본값이 됩니다. GitLab은 OpenSSL 3을 포함하고 있으므로 운영 체제를 변경할 필요가 없습니다.

OpenSSL 3으로 업그레이드하면:

- GitLab은 모든 나가는 TLS 연결과 들어오는 TLS 연결에 TLS 1.2 이상이 필요합니다.
- TLS/SSL 인증서는 최소 112비트의 보안을 가져야 합니다. 2048비트보다 짧은 RSA, DSA, DH 키 및 224비트보다 짧은 ECC 키는 금지됩니다.

자세한 내용은 [GitLab 17.5 변경 사항](https://docs.gitlab.com/update/versions/gitlab_17_changes/#1750)을 참조하세요.

## GitLab 17.6 {#gitlab-176}

### Debian 10 지원 {#support-for-debian-10}

- GitLab 17.3에서 발표됨
- GitLab 17.6에서 제거됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8607)를 참조하세요.

장기 서비스 및 지원(LTSS) [Debian 10은 2024년 6월에 종료되었습니다](https://wiki.debian.org/LTS).

따라서 Linux 패키지 설치에서 더 이상 Debian 10 배포판을 지원하지 않습니다. 사용자는 계속 지원을 받기 위해 Debian 11 또는 Debian 12로 업그레이드해야 합니다.

## GitLab 17.4 {#gitlab-174}

### 파이프라인 보기에서 Needs 탭이 제거됨 {#removed-needs-tab-from-the-pipeline-view}

- GitLab 17.1에서 발표됨
- GitLab 17.4에서 제거됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/336560)를 참조하세요.

파이프라인 보기에서 Needs 탭을 제거합니다. 이는 **작업 의존성** 그룹화 옵션으로 표시된 일반 파이프라인 보기의 정보를 복제하기 때문입니다. 앞으로 메인 파이프라인 그래프의 보기를 계속 개선할 계획입니다.

## GitLab 17.3 {#gitlab-173}

### FIPS 준수 보안 분석기는 UBI Minimal에서 UBI Micro로 변경됩니다 {#fips-compliant-secure-analyzers-will-change-from-ubi-minimal-to-ubi-micro}

- GitLab 17.2에서 발표됨
- GitLab 17.3에서 제거됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/471869)를 참조하세요.

코드의 보안 취약성을 스캔하는 데 사용되는 분석기의 기본 이미지를 업데이트하고 있습니다. 이미 Red Hat Universal Base Image(UBI)를 기반으로 하는 분석기 이미지만 변경하고 있으므로 이 변경 사항은 보안 스캔을 위해 [FIPS 모드](https://docs.gitlab.com/development/fips_compliance/)를 명시적으로 활성화한 경우에만 영향을 줍니다. GitLab 보안 스캔에서 사용하는 기본 이미지는 UBI를 기반으로 하지 않으므로 영향을 받지 않습니다.

GitLab 17.3에서 UBI 기반 분석기의 기본 이미지를 UBI Minimal에서 [UBI Micro](https://www.redhat.com/en/blog/introduction-ubi-micro)로 변경합니다. UBI Micro에는 불필요한 패키지가 더 적고 패키지 관리자가 생략되어 있습니다. 업데이트된 이미지는 더 작아질 것이며 운영 체제에서 제공하는 패키지의 취약성이 더 적게 영향을 받을 것입니다.

GitLab 지원팀의 [지원 문명](https://about.gitlab.com/support/statement-of-support/#ci-cd-templates)은 분석기 이미지의 특정 내용에 의존하는 것을 포함한 문서화되지 않은 사용자 지정 항목을 제외합니다. 예를 들어 `before_script`에서 추가 패키지를 설치하는 것은 지원되는 수정 사항이 아닙니다. 그럼에도 불구하고 이 유형의 사용자 지정에 의존하는 경우 [이 변경 사항의 사용 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/471869#action-required)를 참조하여 이 변경 사항에 대응하는 방법을 알아보거나 현재 사용자 지정에 대한 피드백을 제공하세요.

## GitLab 17.0 {#gitlab-170}

### Kubernetes용 에이전트 옵션 `ca-cert-file` 이름이 변경됨 {#agent-for-kubernetes-option-ca-cert-file-renamed}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/437728)를 참조하세요.

GitLab Kubernetes용 에이전트(agentk)에서 `--ca-cert-file` 명령줄 옵션과 해당 `config.caCert` Helm 차트 값의 이름이 각각 `--kas-ca-cert-file` 및 `config.kasCaCert`로 변경되었습니다.

이전 `--ca-cert-file` 및 `config.caCert` 옵션은 사용 중단되었으며 GitLab 17.0에서 제거됩니다.

### Auto DevOps Herokuish 지원이 사용 중단됨 {#auto-devops-support-for-herokuish-is-deprecated}

- GitLab 15.8에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/211643)를 참조하세요.

Auto DevOps Herokuish 지원은 [Cloud Native Buildpacks](https://docs.gitlab.com/topics/autodevops/stages/#auto-build-using-cloud-native-buildpacks) 지원 중단되었습니다. [Herokuish에서 Cloud Native Buildpacks로 빌드를 마이그레이션해야 합니다](https://docs.gitlab.com/topics/autodevops/stages/#moving-from-herokuish-to-cloud-native-buildpacks). GitLab 14.0부터 Auto Build는 기본적으로 Cloud Native Buildpacks을 사용합니다.

Cloud Native Buildpacks는 자동 테스트를 지원하지 않으므로 Auto DevOps의 Auto Test 기능도 사용 중단됩니다.

### 대시(-) 문자가 있는 자동 생성된 Markdown 앵커 링크`-` {#autogenerated-markdown-anchor-links-with-dash---characters}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/440733)를 참조하세요.

GitLab은 모든 제목에 대해 자동으로 앵커 링크를 만들어 Markdown 문서 또는 wiki 페이지의 특정 위치로 링크할 수 있습니다. 그러나 일부 엣지 케이스에서는 자동 생성된 앵커가 많은 사용자가 예상하는 것보다 더 적은 대시(`-`) 문자로 생성됩니다. 예를 들어, 제목이 `## Step - 1`인 경우, 대부분의 다른 Markdown 도구 및 린터는 `#step---1`을 예상합니다. 그러나 GitLab은 연속 대시가 1개로 압축된 `#step-1` 앵커를 생성합니다.

GitLab 17.0에서는 연속 대시를 더 이상 제거하지 않음으로써 자동 생성된 앵커를 업계 표준과 일치시킵니다. 17.0에서 대시가 여러 개인 제목으로 링크할 수 있는 Markdown 문서가 있는 경우 이 엣지 케이스를 피하기 위해 제목을 업데이트해야 합니다. 위의 예제를 사용하여 `## Step - 1`을 `## Step 1`로 변경하여 페이지 내 링크가 계속 작동하도록 할 수 있습니다.

### CiRunner.projects 기본 정렬이 `id_desc`로 변경됨 {#cirunnerprojects-default-sort-is-changing-to-id_desc}

- GitLab 16.0에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/372117)를 참조하세요.

`CiRunner.projects` 필드의 기본 정렬 순서 값이 `id_asc`에서 `id_desc`로 변경됩니다. 반환된 프로젝트의 순서가 `id_asc`이어야 하는 경우 스크립트를 변경하여 선택을 명시적으로 하세요.

### 일반 설정의 컴플라이언스 프레임워크 {#compliance-framework-in-general-settings}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/422783)를 참조하세요.

컴플라이언스 프레임워크 관리를 [컴플라이언스 센터](https://docs.gitlab.com/user/compliance/compliance_center/)의 프레임워크 및 프로젝트 보고서로 이동했습니다.

따라서 GitLab 17.0에서는 그룹 및 프로젝트의 **일반** 설정 페이지에서 컴플라이언스 프레임워크 관리를 제거합니다.

### Swift 및 OSS 스토리지 드라이버에 대한 컨테이너 레지스트리 지원 {#container-registry-support-for-the-swift-and-oss-storage-drivers}

- GitLab 16.6에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/container-registry/-/issues/1141)를 참조하세요.

컨테이너 레지스트리는 저장소 드라이버를 사용하여 다양한 객체 저장소 플랫폼과 함께 작동합니다. 각 드라이버의 코드는 상대적으로 자체 포함되어 있지만 이러한 드라이버의 유지 관리 부담이 큽니다. 각 드라이버 구현은 고유하며 드라이버를 변경하려면 해당 특정 드라이버에 대한 높은 수준의 도메인 전문 지식이 필요합니다.

유지 관리 비용을 줄이려는 노력의 일환으로 OSS(Object Storage Service) 및 OpenStack Swift 지원을 중단합니다. 둘 다 이미 업스트림 Docker Distribution에서 제거되었습니다. 이를 통해 컨테이너 레지스트리를 더 넓은 GitLab 제품 제공과 [객체 저장소 지원](https://docs.gitlab.com/administration/object_storage/#supported-object-storage-providers)과 일치시킵니다.

OSS에는 [S3 호환성 모드](https://www.alibabacloud.com/help/en/oss/developer-reference/compatibility-with-amazon-s3)가 있으므로 지원되는 드라이버로 마이그레이션할 수 없으면 사용을 고려하세요. Swift는 [S3 API 작업과 호환되며](https://docs.openstack.org/swift/latest/s3_compat.html) S3 저장소 드라이버에서도 필요합니다.

### DAST ZAP 고급 구성 변수 사용 중단 {#dast-zap-advanced-configuration-variables-deprecation}

- GitLab 15.7에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/383467)를 참조하세요.

GitLab 15.7에서 새로운 브라우저 기반 DAST 분석기 GA를 통해 향후 어느 시점에서 기본 DAST 분석기로 만드는 작업을 하고 있습니다. 이를 준비하기 위해 다음의 레거시 DAST 변수가 사용 중단되며 GitLab 17.0에서 제거될 예정입니다: `DAST_ZAP_CLI_OPTIONS` 및 `DAST_ZAP_LOG_CONFIGURATION`. 이러한 변수는 OWASP ZAP을 기반으로 하는 레거시 DAST 분석기의 고급 구성을 허용했습니다. 새로운 브라우저 기반 분석기에는 ZAP이 작동하는 방식에 특정한 동일한 기능이 포함되지 않습니다.

이 세 개의 변수는 GitLab 17.0에서 제거될 것입니다.

### 종속성 검사 잘못된 SBOM 메타데이터 속성 {#dependency-scanning-incorrect-sbom-metadata-properties}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/438779)를 참조하세요.

GitLab 17.0은 CycloneDX SBOM 보고서의 다음 메타데이터 속성에 대한 지원을 제거합니다:

- `gitlab:dependency_scanning:input_file`
- `gitlab:dependency_scanning:package_manager`

이 속성들은 GitLab 15.7에서 종속성 검사에서 생성된 SBOM에 추가되었습니다. 그러나 이 속성들은 잘못되었으며 [GitLab CycloneDX 속성 분류법](https://docs.gitlab.com/development/sec/cyclonedx_property_taxonomy/)과 일치하지 않았습니다. 다음의 올바른 속성들이 GitLab 15.11에 추가되어 이를 해결했습니다:

- `gitlab:dependency_scanning:input_file:path`
- `gitlab:dependency_scanning:package_manager:name`

잘못된 속성들은 이전 버전과의 호환성을 위해 유지되었습니다. 현재 사용 중단되며 17.0에서 제거됩니다.

### sbt 1.0.X에 대한 종속성 검사 지원 {#dependency-scanning-support-for-sbt-10x}

- GitLab 16.8에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/415835)를 참조하세요.

매우 오래된 sbt 버전의 지원은 유지 보수 비용을 증가시키지 않으면서 이 패키지 관리자에 대한 추가 사용 사례 지원을 개선하는 것을 방지하고 있습니다.

sbt 버전 1.1.0은 6년 전에 출시되었으며 사용자는 1.0.x에서 업그레이드할 것을 권고합니다. 종속성 검사는 더 이상 작동하지 않을 것입니다.

### 임시 저장소 증가와 관련된 GraphQL 필드 사용 중단 {#deprecate-graphql-fields-related-to-the-temporary-storage-increase}

- GitLab 16.7에서 발표됨
- GitLab 17.0에서 제거됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/385720)를 참조하세요.

GraphQL 필드 `isTemporaryStorageIncreaseEnabled` 및 `temporaryStorageIncreaseEndsOn`는 사용 중단되었습니다. 이 GraphQL 필드들은 임시 저장소 증가 프로젝트와 관련이 있습니다. 프로젝트가 취소되었고 필드가 사용되지 않았습니다.

### 컨테이너 스캔을 위한 Grype 스캐너 사용 중단 {#deprecate-grype-scanner-for-container-scanning}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/439164)를 참조하세요.

GitLab 컨테이너 스캔 분석기의 Grype 스캐너 지원은 GitLab 16.9에서 사용 중단되었습니다.

GitLab 17.0부터 Grype 분석기는 더 이상 유지되지 않으며 [지원 문명](https://about.gitlab.com/support/statement-of-support/#version-support)에 설명된 대로 제한된 수정 사항만 지원됩니다.

사용자는 Trivy 스캐너를 사용하는 `CS_ANALYZER_IMAGE`의 기본 설정을 사용할 것을 권장합니다.

기존 현재 주요 버전의 Grype 분석기 이미지는 GitLab 19.0까지 최신 권고 사항 데이터베이스 및 운영 체제 패키지로 계속 업데이트되며, 그 시점에서 분석기는 작동 중지될 것입니다.

19.0 이후 Grype을 계속 사용하려면 [보안 스캐너 통합 문서](https://docs.gitlab.com/development/integrations/secure/)를 참조하여 GitLab과의 자신의 통합을 만드는 방법을 알아보세요.

### 라이선스 스캔 CI 템플릿 사용 중단 {#deprecate-license-scanning-ci-templates}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/439157)를 참조하세요.

GitLab 17.0은 라이선스 스캔 CI 템플릿을 제거합니다:

- [`Jobs/License-Scanning.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/6d9956863d3cd066edc50a29767c2cd4a939c6fd/lib/gitlab/ci/templates/Jobs/License-Scanning.gitlab-ci.yml)
- [`Jobs/License-Scanning.latest.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/6d9956863d3cd066edc50a29767c2cd4a939c6fd/lib/gitlab/ci/templates/Jobs/License-Scanning.latest.gitlab-ci.yml)
- [`Security/License-Scanning.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/6d9956863d3cd066edc50a29767c2cd4a939c6fd/lib/gitlab/ci/templates/Security/License-Scanning.gitlab-ci.yml)

위의 템플릿 중 하나를 포함하는 CI 구성은 GitLab 17.0에서 작동 중지될 것입니다.

사용자는 대신 [CycloneDX 파일의 라이선스 스캔](https://docs.gitlab.com/user/compliance/license_scanning_of_cyclonedx_files/)을 사용할 것을 권장합니다.

### 종속성 검사 및 라이선스 검사에서 Python 3.9 사용 중단 {#deprecate-python-39-in-dependency-scanning-and-license-scanning}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/441201)를 참조하세요.

GitLab 16.9부터 종속성 검사 및 라이선스 스캔의 Python 3.9 지원은 사용 중단됩니다. GitLab 17.0에서 Python 3.10이 종속성 검사 CI/CD 작업의 기본 버전입니다.

GitLab 17.0부터 종속성 검사 및 라이선스 스캔 기능은 [호환 lockfile](https://docs.gitlab.com/user/application_security/dependency_scanning/#obtaining-dependency-information-by-parsing-lockfiles) 없이 Python 3.9가 필요한 프로젝트를 지원하지 않을 것입니다.

### GitLab Runner에서 Windows CMD 사용 중단 {#deprecate-windows-cmd-in-gitlab-runner}

- GitLab 16.1에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/414864)를 참조하세요.

GitLab 11.11에서 Windows Batch 실행기, CMD 셸은 PowerShell을 지원하기 위해 GitLab Runner에서 사용 중단되었습니다. 그 이후로 CMD 셸은 GitLab Runner에서 계속 지원되었습니다. 그러나 이로 인해 엔지니어링 팀과 Windows의 Runner를 사용하는 고객 모두에게 추가 복잡성이 발생했습니다. 우리는 GitLab Runner 17.0에서 Windows CMD 지원을 완전히 제거할 계획입니다. 고객은 Windows의 Runner를 Shell 실행기와 함께 사용할 때 PowerShell을 사용할 계획을 해야 합니다. 고객은 제거 이슈, [이슈 29479](https://gitlab.com/gitlab-org/gitlab-runner/-/issues/29479)에서 피드백을 제공하거나 질문을 할 수 있습니다.

### `CiRunner` GraphQL 필드가 `CiRunnerManager`에서 중복됨 {#deprecate-cirunner-graphql-fields-duplicated-in-cirunnermanager}

- GitLab 16.2에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/415185)를 참조하세요.

이 필드(`architectureName`, `ipAddress`, `platformName`, `revision`, `version`)는 이제 [GraphQL `CiRunner`](https://docs.gitlab.com/api/graphql/reference/objects/#cirunner) 타입에서 사용 중단되었습니다. 이는 실행기 구성 내에서 그룹화된 실행기 관리자의 도입으로 복제되기 때문입니다.

### Terraform 모듈 CI/CD 템플릿에서 `fmt` 작업 사용 중단 {#deprecate-fmt-job-in-terraform-module-cicd-template}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/440249)를 참조하세요.

Terraform 모듈 CI/CD 템플릿의 `fmt` 작업은 사용 중단되며 GitLab 17.0에서 제거될 것입니다. 이는 다음 템플릿에 영향을 미칩니다:

- `Terraform-Module.gitlab-ci.yml`
- `Terraform/Module-Base.gitlab-ci.yml`

파이프라인에 수동으로 Terraform `fmt` 작업을 다시 추가할 수 있습니다:

```yaml
fmt:
  image: hashicorp/terraform
  script: terraform fmt -chdir "$TF_ROOT" -check -diff -recursive
```

[OpenTofu CI/CD 구성 요소](https://gitlab.com/components/opentofu)에서 `fmt` 템플릿을 사용할 수도 있습니다.

### 취약성 관리 기능에서 `message` 필드 사용 중단 {#deprecate-message-field-from-vulnerability-management-features}

- GitLab 16.1에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/411573)를 참조하세요.

이 머지 리퀘스트는 `VulnerabilityCreate` GraphQL 변형의 `message` 필드와 취약성 내보내기의 `AdditionalInfo` 열을 사용 중단합니다. 메시지 필드는 GitLab 16.0의 보안 보고서 스키마에서 제거되었으며 더 이상 다른 곳에서 사용되지 않습니다.

### GitLab Runner Kubernetes 실행기에서 `terminationGracePeriodSeconds` 사용 중단 {#deprecate-terminationgraceperiodseconds-in-the-gitlab-runner-kubernetes-executor}

- GitLab 16.3에서 발표됨
- GitLab 17.0에서 지원 종료
- GitLab 17.0에서 제거됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab-runner/-/issues/28165)를 참조하세요.

GitLab Runner Kubernetes 실행기 설정인 `terminationGracePeriodSeconds`는 사용 중단되며 GitLab 17.0에서 제거될 것입니다. Kubernetes의 GitLab Runner 워커 포드의 정리 및 종료를 관리하려면 고객이 대신 `cleanupGracePeriodSeconds` 및 `podTerminationGracePeriodSeconds`을 구성해야 합니다. `cleanupGracePeriodSeconds` 및 `podTerminationGracePeriodSeconds` 사용 방법에 대한 정보는 [GitLab Runner 실행기 문서](https://docs.gitlab.com/runner/executors/kubernetes/#other-configtoml-settings)를 참조하세요.

### 기능 플래그 API에서 `version` 필드 사용 중단 {#deprecate-version-field-in-feature-flag-api}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/437986)를 참조하세요.

[기능 플래그 REST API](https://docs.gitlab.com/api/feature_flags/)의 `version` 필드는 사용 중단되며 GitLab 17.0에서 제거될 것입니다.

`version` 필드가 제거된 후에는 레거시 기능 플래그를 만드는 방법이 없을 것입니다.

### 개발자 역할의 취약성 상태 변경 사용 중단 {#deprecate-change-vulnerability-status-from-the-developer-role}

- GitLab 16.4에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/424133)를 참조하세요.

개발자가 취약성의 상태를 변경할 수 있는 능력은 이제 사용 중단되었습니다. 우리는 향후 GitLab 17.0 릴리스에서 개발자 역할에서 이 기능을 제거하기 위한 주요 변경 사항을 계획하고 있습니다. 개발자에게 이 권한을 계속 부여하려는 사용자는 [개발자용 사용자 지정 역할을 만들고](https://docs.gitlab.com/user/permissions/#custom-roles) 이들에게 이 액세스를 부여하기 위해 `admin_vulnerability` 권한을 추가할 수 있습니다.

### GitLab Self-Managed의 그룹 소유자용 사용자 지정 역할 생성 사용 중단 {#deprecate-custom-role-creation-for-group-owners-on-gitlab-self-managed}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/439284)를 참조하세요.

GitLab Self-Managed 17.0에서는 그룹 소유자에 대한 사용자 지정 역할 생성이 제거됩니다. 이 기능은 관리자만 인스턴스 수준으로 이동합니다. 그룹 소유자는 그룹 수준에서 사용자 지정 역할을 할당할 수 있습니다.

GitLab.com의 그룹 소유자는 계속해서 사용자 지정 역할을 관리하고 그룹 수준에서 할당할 수 있습니다.

API를 사용하여 GitLab Self-Managed에서 사용자 지정 역할을 관리하는 경우 새 인스턴스 엔드포인트가 추가되었으며 API 작업을 계속하려면 필수입니다.

- 인스턴스의 모든 멤버 역할 나열 - `GET /api/v4/member_roles`
- 인스턴스에 멤버 역할 추가 - `POST /api/v4/member_roles`
- 인스턴스에서 멤버 역할 제거 - `DELETE /api/v4/member_roles/:id`

### GraphQL VulnerabilityType에서 `hasSolutions` 필드 사용 중단 {#deprecate-field-hassolutions-from-graphql-vulnerabilitytype}

- GitLab 16.3에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/414895)를 참조하세요.

GraphQL 필드 `Vulnerability.hasSolutions`는 사용 중단되며 GitLab 17.0에서 제거될 것입니다. 대신 `Vulnerability.hasRemediations`를 사용하세요.

### 레거시 셸 이스케이핑 및 인용 실행기 셸 실행기 사용 중단 {#deprecate-legacy-shell-escaping-and-quoting-runner-shell-executor}

- GitLab 15.11에서 발표됨
- GitLab 17.0에서 제거됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/406679)를 참조하세요.

실행기의 레거시 이스케이프 시퀀스 메커니즘은 변수 확장을 처리하는 부분적 ANSI-C 인용의 최적이 아닌 구현을 구현합니다. 이 방법은 실행기가 큰따옴표에 포함된 인수를 확장한다는 것을 의미합니다. 15.11부터 실행기 셸 실행기에서 레거시 이스케이핑 및 인용 메서드를 사용 중단하고 있습니다.

### 로그인 페이지의 사용자 지정 텍스트와 관련된 사용 중단된 매개 변수 {#deprecated-parameters-related-to-custom-text-in-the-sign-in-page}

- GitLab 16.2에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/124461)를 참조하세요.

`sign_in_text` 및 `help_text` 매개 변수는 [설정 API](https://docs.gitlab.com/api/settings/)에서 사용 중단됩니다. 로그인 및 새 사용자 계정 페이지에 사용자 지정 텍스트를 추가하려면 [모양 API](https://docs.gitlab.com/api/appearance/)에서 `description` 필드를 사용하세요.

### Windows Server 2019를 2022로 지원 중단 {#deprecating-windows-server-2019-in-favor-of-2022}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/438554)를 참조하세요.

최근에 Windows Server 2022의 GitLab.com 실행기 Windows 베타 버전을 출시했습니다. 함께 Windows 2019를 GitLab 17.0에서 사용 중단합니다.

Windows 2022로 마이그레이션하는 방법에 대한 자세한 내용은 [GitLab.com 실행기에서 Windows 2022 지원 이제 사용 가능](https://about.gitlab.com/blog/windows-2022-support-for-gitlab-saas-runners/)을 참조하세요.

### DingTalk OmniAuth 공급자 {#dingtalk-omniauth-provider}

- GitLab 15.10에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/390855)를 참조하세요.

GitLab에 DingTalk OmniAuth 공급자를 제공하는 `omniauth-dingtalk` gem은 다음 주요 릴리스인 GitLab 17.0에서 제거될 것입니다. 이 gem은 사용이 매우 적으며 JiHu 버전에 더 적합합니다.

### Gitaly 구성의 중복 저장소 {#duplicate-storages-in-gitaly-configuration}

- GitLab 16.10에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitaly/-/issues/5598)를 참조하세요.

동일한 저장소 경로를 가리키는 여러 Gitaly 저장소를 구성하는 지원은 사용 중단되며 GitLab 17.0에서 제거될 것입니다. GitLab 17.0 이상에서는 이 유형의 구성으로 인해 오류가 발생합니다.

이 유형의 구성에 대한 지원을 제거하고 있습니다. 백그라운드 리포지토리 유지 관리에 문제가 발생할 수 있고 향후 Gitaly 저장소 구현과 호환되지 않기 때문입니다.

인스턴스 관리자는 `gitlab.rb` 구성 파일의 `gitaly['configuration']` 섹션의 `storage` 항목을 업데이트하여 각 저장소가 고유한 경로로 구성되도록 해야 합니다.

### 다운스트림 파이프라인에서 수정된 파일 타입 변수 확장 {#file-type-variable-expansion-fixed-in-downstream-pipelines}

- GitLab 16.6에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/419445)를 참조하세요.

이전에는 [파일 타입 CI/CD 변수](https://docs.gitlab.com/ci/variables/#use-file-type-cicd-variables)를 다른 CI/CD 변수에서 참조하려고 했을 때 CI/CD 변수가 파일의 내용을 포함하도록 확장되었습니다. 이 동작은 일반적인 셸 변수 확장 규칙을 준수하지 않았기 때문에 잘못되었습니다. CI/CD 변수 참조는 파일 자체의 내용이 아닌 파일의 경로만 포함하도록 확장되어야 합니다. 이는 [대부분의 사용 사례에서 GitLab 15.7에서 수정되었습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/29407). 불행하게도 다운스트림 파이프라인으로 CI/CD 변수를 전달하는 것은 아직 수정되지 않은 엣지 케이스였지만 이제 GitLab 17.0에서 수정될 것입니다.

이 변경으로 `.gitlab-ci.yml` 파일에서 구성된 변수는 파일 변수를 참조하고 다운스트림 파이프라인으로 전달할 수 있으며 파일 변수도 다운스트림 파이프라인으로 전달될 것입니다. 다운스트림 파이프라인은 변수 참조를 파일 내용이 아닌 파일 경로로 확장할 것입니다.

이 주요 변경 사항은 다운스트림 파이프라인에서 파일 변수를 확장하는 것에 의존하는 사용자 워크플로우를 중단할 수 있습니다.

### Geo: 설계 및 프로젝트에 대한 레거시 복제 세부 정보 경로 사용 중단 {#geo-legacy-replication-details-routes-for-designs-and-projects-deprecated}

- GitLab 16.4에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/424002)를 참조하세요.

레거시 데이터 타입의 [Geo 자체 서비스 프레임워크](https://docs.gitlab.com/development/geo/framework/)로의 마이그레이션의 일환으로 다음의 복제 세부 정보 경로가 사용 중단됩니다:

- 설계 `/admin/geo/replication/designs` `/admin/geo/sites/<Geo Node/Site ID>/replication/design_management_repositories`로 바뀜
- 프로젝트 `/admin/geo/replication/projects` `/admin/geo/sites/<Geo Node/Site ID>/replication/projects`로 바뀜

GitLab 16.4부터 17.0까지 레거시 경로의 조회는 자동으로 새 경로로 리디렉션됩니다. 17.0에서 리디렉션을 제거할 것입니다. 레거시 경로를 사용할 수 있는 책갈피 또는 스크립트를 업데이트하세요.

### GitLab Helm 차트 값 `gitlab.kas.privateApi.tls.*` 사용 중단 {#gitlab-helm-chart-values-gitlabkasprivateapitls-are-deprecated}

- GitLab 15.8에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/4097)를 참조하세요.

KAS와 Helm 차트 구성 요소 간의 TLS 통신을 용이하게 하기 위해 `global.kas.tls.*` Helm 값을 도입했습니다. 이전 값 `gitlab.kas.privateApi.tls.enabled` 및 `gitlab.kas.privateApi.tls.secretName`은 사용 중단되었으며 GitLab 17.0에서 제거될 예정입니다.

새 값은 KAS에 대한 TLS을 활성화하는 간소화된 포괄적인 방법을 제공하므로 `gitlab.kas.privateApi.tls.*` 대신 `global.kas.tls.*`을 사용해야 합니다. `gitlab.kas.privateApi.tls.*` 자세한 정보는:

- `global.kas.tls.*` 값을 도입하는 [머지 리퀘스트](https://gitlab.com/gitlab-org/charts/gitlab/-/merge_requests/2888).
- [사용 중단된 `gitlab.kas.privateApi.tls.*` 문서](https://docs.gitlab.com/charts/charts/gitlab/kas/#enable-tls-communication-through-the-gitlabkasprivateapi-attributes-deprecated).
- [새로운 `global.kas.tls.*` 문서](https://docs.gitlab.com/charts/charts/globals/#tls-settings-1).

### GitLab Runner 원본 메타데이터 SLSA v0.2 문명 {#gitlab-runner-provenance-metadata-slsa-v02-statement}

- GitLab 16.8에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab-runner/-/issues/36869)를 참조하세요.

실행기는 원본 메타데이터를 생성하며 현재 기본값은 SLSA v0.2를 준수하는 문명 생성입니다. SLSA v1.0이 출시되었으며 이제 GitLab에서 지원되기 때문에 v0.2 문명은 이제 사용 중단되었으며 GitLab 17.0에서 제거할 계획입니다. SLSA v1.0 문명은 GitLab 17.0의 새로운 기본 문명 형식이 될 예정입니다.

### 지원되지 않는 방법을 통한 GraphQL API 액세스 {#graphql-api-access-through-unsupported-methods}

- GitLab 17.0에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/442520)를 참조하세요.

GitLab 17.0부터는 GraphQL에 대한 액세스를 [이미 문서화된 지원되는 토큰 타입](https://docs.gitlab.com/api/graphql/#token-authentication)을 통해서만 제한합니다.

이미 문서화되고 지원되는 토큰 타입을 사용하는 고객의 경우 주요 변경 사항이 없습니다.

### GraphQL `networkPolicies` 리소스 사용 중단 {#graphql-networkpolicies-resource-deprecated}

- GitLab 14.8에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/421440)를 참조하세요.

`networkPolicies` [GraphQL 리소스](https://docs.gitlab.com/api/graphql/reference/#projectnetworkpolicies)는 사용 중단되었으며 GitLab 17.0에서 제거될 것입니다. GitLab 15.0 이후 이 필드는 데이터를 반환하지 않았습니다.

### GraphQL 필드 `confidential`이(가) 노트에서 `internal`로 변경됨 {#graphql-field-confidential-changed-to-internal-on-notes}

- GitLab 15.5에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/371485)를 참조하세요.

`Note`에 대한 `confidential` 필드는 사용 중단되며 `internal`로 이름이 바뀔 것입니다.

### GraphQL 필드 `registrySizeEstimated` 사용 중단됨 {#graphql-field-registrysizeestimated-has-been-deprecated}

- GitLab 16.2에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/416509)를 참조하세요.

명확히 하기 위해 GraphQL 필드 `registrySizeEstimated`은(는) `containerRegistrySizeIsEstimated`로 이름이 바뀌었습니다. `registrySizeEstimated`은 GitLab 16.2에서 사용 중단되었으며 GitLab 17.0에서 제거될 것입니다. 대신 GitLab 16.2에서 도입된 `containerRegistrySizeIsEstimated`를 사용하세요.

### GraphQL 필드 `totalWeight` 사용 중단 {#graphql-field-totalweight-is-deprecated}

- GitLab 16.3에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/416219)를 참조하세요.

GraphQL을 사용하여 이슈 보드의 문제 총 가중치를 쿼리할 수 있습니다. 그러나 `totalWeight` 필드는 최대 크기 2147483647로 제한됩니다. 결과적으로 `totalWeight`는 사용 중단되었으며 GitLab 17.0에서 제거될 것입니다.

대신 GitLab 16.2에서 도입된 `totalIssueWeight`을 사용하세요.

### GraphQL 타입 `RunnerMembershipFilter` `CiRunnerMembershipFilter`로 이름 변경 {#graphql-type-runnermembershipfilter-renamed-to-cirunnermembershipfilter}

- GitLab 16.0에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/409333)를 참조하세요.

GraphQL 타입 `RunnerMembershipFilter`은(는) `CiRunnerMembershipFilter`로 이름이 바뀌었습니다. GitLab 17.0에서 `RunnerMembershipFilter` 타입의 별칭 지정이 제거될 것입니다.

### GraphQL: `SharedRunnersSetting` 열거형의 `DISABLED_WITH_OVERRIDE` 값은 사용 중단됨 {#graphql-the-disabled_with_override-value-for-the-sharedrunnerssetting-enum-is-deprecated}

- GitLab 15.8에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/385636)를 참조하세요.

GitLab 17.0에서 `SharedRunnersSetting` GraphQL 열거형 타입의 `DISABLED_WITH_OVERRIDE` 값은 제거될 것입니다. 대신 `DISABLED_AND_OVERRIDABLE`를 사용하세요.

### GraphQL: `canDestroy` 및 `canDelete` 지원 사용 중단 {#graphql-deprecate-support-for-candestroy-and-candelete}

- GitLab 16.6에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/390754)를 참조하세요.

패키지 레지스트리 사용자 인터페이스는 GitLab GraphQL API를 사용합니다. 모두가 기여하기 쉽게 하려면 프론트엔드가 모든 GitLab 제품 영역에서 일관되게 코드화되는 것이 중요합니다. 그러나 GitLab 16.6 이전에는 패키지 레지스트리 UI가 제품의 다른 영역과 다르게 권한을 처리했습니다.

16.6에서 `Types::PermissionTypes::Package` 타입 아래에 새로운 `UserPermissions` 필드를 추가하여 패키지 레지스트리를 GitLab의 나머지 부분과 정렬했습니다. 이 새 필드는 `Package`, `PackageBase` 및 `PackageDetailsType` 타입의 `canDestroy` 필드를 대체합니다. 또한 `ContainerRepository`, `ContainerRepositoryDetails` 및 `ContainerRepositoryTag`에 대한 `canDelete` 필드를 대체합니다. GitLab 17.0에서 `canDestroy` 및 `canDelete` 필드가 제거될 것입니다.

이는 17.0에서 완료될 주요 변경 사항입니다.

### HashiCorp Vault 통합은 기본적으로 `CI_JOB_JWT` CI/CD 작업 토큰을 더 이상 사용하지 않을 것입니다 {#hashicorp-vault-integration-will-no-longer-use-the-ci_job_jwt-cicd-job-token-by-default}

- GitLab 15.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/366798)를 참조하세요.

JWT 및 OIDC를 사용하여 CI 워크플로우의 보안을 개선하기 위한 노력의 일환으로 네이티브 HashiCorp 통합도 GitLab 16.0에서 업데이트됩니다. [`secrets:vault`](https://docs.gitlab.com/ci/yaml/#secretsvault) 키워드를 사용하여 Vault에서 비밀을 검색하는 프로젝트는 [ID 토큰을 사용하도록 구성](https://docs.gitlab.com/ci/secrets/id_token_authentication/#configure-automatic-id-token-authentication)되어야 합니다. ID 토큰은 15.7에서 도입되었습니다.

이 변경을 준비하려면 새로운 [`id_tokens`](https://docs.gitlab.com/ci/yaml/#id_tokens) 키워드를 사용하고 `aud` 청구를 구성하세요. 바운드 대상이 `https://`로 시작하는지 확인하세요.

GitLab 15.9~15.11에서 [**JSON 웹 토큰(JWT) 액세스 제한** 설정을 활성화](https://docs.gitlab.com/ci/secrets/id_token_authentication/#enable-automatic-id-token-authentication)할 수 있습니다. 이렇게 하면 이전 토큰이 작업에 노출되지 않고 [`secrets:vault` 키워드에 대한 ID 토큰 인증](https://docs.gitlab.com/ci/secrets/id_token_authentication/#configure-automatic-id-token-authentication)이 활성화됩니다.

GitLab 16.0 이상에서:

- 이 설정은 제거될 것입니다.
- `id_tokens` 키워드를 사용하는 CI/CD 작업은 `secrets:vault`를 사용하는 ID 토큰을 사용할 수 있으며 `CI_JOB_JWT*` 토큰이 사용 가능하지 않습니다.
- `id_tokens` 키워드를 사용하지 않는 작업은 GitLab 17.0까지 `CI_JOB_JWT*` 토큰을 계속 사용할 수 있습니다.

### Auto DevOps 빌드의 Heroku 이미지 업그레이드 {#heroku-image-upgrade-in-auto-devops-build}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/437937)를 참조하세요.

GitLab 17.0에서 `auto-build-image` 프로젝트는 `heroku/builder:20` 이미지에서 `heroku/builder:22`으로 업그레이드될 것입니다.

새 이미지의 동작을 테스트하려면 CI/CD 변수 `AUTO_DEVOPS_BUILD_IMAGE_CNB_BUILDER`을 `heroku/builder:22`로 설정하세요.

GitLab 17.0 이후 `heroku/builder:20`을 계속 사용하려면 `AUTO_DEVOPS_BUILD_IMAGE_CNB_BUILDER`을를 `heroku/builder:20`으로 설정하세요.

### 내부 컨테이너 레지스트리 API 태그 삭제 엔드포인트 {#internal-container-registry-api-tag-deletion-endpoint}

- GitLab 16.4에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/container-registry/-/issues/1094)를 참조하세요.

Docker 레지스트리 HTTP API V2 사양은 나중에 [OCI 배포 사양](https://github.com/opencontainers/distribution-spec/blob/main/spec.md)으로 대체되었으며 태그 삭제 작업을 포함하지 않았습니다. 동일한 목표를 달성하기 위해 안전하지 않고 느린 해결 방법(매니페스트 삭제, 태그 삭제 아님)을 사용해야 했습니다.

태그 삭제는 중요한 기능이므로 GitLab 컨테이너 레지스트리에 태그 삭제 작업을 추가하여 V2 API를 Docker 및 OCI 배포 스펙의 범위를 초과하여 확장했습니다.

그 이후로 OCI 배포 사양이 업데이트되었으며 이제 [`DELETE /v2/<name>/manifests/<tag>` 엔드포인트](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#deleting-tags)를 사용하는 태그 삭제 작업이 있습니다.

이는 컨테이너 레지스트리에 정확히 동일한 기능을 제공하는 두 개의 엔드포인트를 남겨둡니다. `DELETE /v2/<name>/tags/reference/<tag>`은 사용자 지정 GitLab 태그 삭제 엔드포인트이고 `DELETE /v2/<name>/manifests/<tag>`은 GitLab 16.4에서 도입된 OCI 준수 태그 삭제 엔드포인트입니다.

사용자 지정 GitLab 태그 삭제 엔드포인트 지원은 GitLab 16.4에서 사용 중단되었으며 GitLab 17.0에서 제거될 것입니다.

이 엔드포인트는 공개 [GitLab 컨테이너 레지스트리 API](https://docs.gitlab.com/api/container_registry/)가 아닌 **내부** 컨테이너 레지스트리 애플리케이션 API에서 사용합니다. 대부분의 컨테이너 레지스트리 사용자는 조치가 필요하지 않습니다. 태그 삭제와 관련된 모든 GitLab UI 및 API 기능은 새로운 OCI 준수 엔드포인트로 전환할 때 손상되지 않습니다.

내부 컨테이너 레지스트리 API에 액세스하고 원래 태그 삭제 엔드포인트를 사용하는 경우 새 엔드포인트로 업데이트해야 합니다.

### JWT `/-/jwks` 인스턴스 엔드포인트는 사용 중단됨 {#jwt--jwks-instance-endpoint-is-deprecated}

- GitLab 16.7에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/221031)를 참조하세요.

GitLab 17.0에서 [이전 JSON 웹 토큰 버전의 사용 중단](https://docs.gitlab.com/update/deprecations/?removal_milestone=17.0#old-versions-of-json-web-tokens-are-deprecated)이 있으므로 연결된 `/-/jwks` 엔드포인트는 `/oauth/discovery/keys`에 대한 별칭이므로 더 이상 필요하지 않으며 제거될 것입니다. 인증 구성에서 `jwks_url`을 지정했다면 구성을 `oauth/discovery/keys`으로 업데이트하고 엔드포인트에서 `/-/jwks` 사용을 모두 제거하세요. 인증 구성에서 `oauth_discovery_keys`을 이미 사용하고 있고 엔드포인트에서 `/-/jwks` 별칭을 사용하고 있다면 엔드포인트에서 `/-/jwks`을 제거하세요. 예를 들어 `https://gitlab.example.com/-/jwks`을를 `https://gitlab.example.com`로 변경하세요.

### 레거시 Geo Prometheus 메트릭 {#legacy-geo-prometheus-metrics}

- GitLab 16.6에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/430192)를 참조하세요.

[Geo 자체 서비스 프레임워크](https://docs.gitlab.com/development/geo/framework/)로의 프로젝트 마이그레이션 다음으로 다수의 [Prometheus](https://docs.gitlab.com/administration/monitoring/prometheus/) 메트릭을 사용 중단했습니다. 다음의 Geo 관련 Prometheus 메트릭은 사용 중단되며 17.0에서 제거될 것입니다. 아래 표는 사용 중단된 메트릭과 각각의 대체 항목을 나열합니다. 대체 항목은 GitLab 16.3.0 이상에서 사용 가능합니다.

| 사용 중단된 메트릭                        |  대체 메트릭                            |
| ---------------------------------------- | ---------------------------------------------- |
| `geo_repositories_synced`                | `geo_project_repositories_synced`              |
| `geo_repositories_failed`                | `geo_project_repositories_failed`              |
| `geo_repositories_checksummed`           | `geo_project_repositories_checksummed`         |
| `geo_repositories_checksum_failed`       | `geo_project_repositories_checksum_failed`     |
| `geo_repositories_verified`              | `geo_project_repositories_verified`            |
| `geo_repositories_verification_failed`   | `geo_project_repositories_verification_failed` |
| `geo_repositories_checksum_mismatch`     |  사용 가능한 항목 없음                                |
| `geo_repositories_retrying_verification` |  사용 가능한 항목 없음                                |

### 라이선스 목록은 사용 중단됨 {#license-list-is-deprecated}

- GitLab 16.8에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/436100)를 참조하세요.

오늘날 GitLab에서는 프로젝트가 사용하는 모든 라이선스 및 해당 라이선스를 사용하는 구성 요소 목록을 라이선스 목록에서 볼 수 있습니다. 16.8부터 라이선스 목록은 사용 중단되었으며 17.0에서 주요 변경 사항으로 제거될 예정입니다. 이제 라이선스로 필터링할 수 있는 기능을 포함하여 프로젝트 또는 그룹이 사용 중인 모든 라이선스에 종속성 목록에서 액세스할 수 있습니다.

### sbt 1.0.X에 대한 라이선스 스캔 지원 {#license-scanning-support-for-sbt-10x}

- GitLab 16.8에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/437591)를 참조하세요.

GitLab 17.0은 sbt 1.0.x에 대한 라이선스 스캔 지원을 제거합니다.

사용자는 sbt 1.0.x에서 업그레이드할 것을 권장합니다.

### Ubuntu 18.04용 Linux 패키지 {#linux-packages-for-ubuntu-1804}

- GitLab 16.8에서 발표됨
- GitLab 17.0에서 제거됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8082)를 참조하세요.

Ubuntu 18.04에 대한 표준 지원 [2023년 6월에 종료되었습니다](https://wiki.ubuntu.com/Releases).

GitLab 17.0부터는 Ubuntu 18.04용 Linux 패키지를 제공하지 않습니다.

GitLab 17.0 이상을 준비하려면:

1. Ubuntu 18.04에서 실행 중인 서버의 GitLab 인스턴스를 Ubuntu 20.04 또는 Ubuntu 22.04로 이동합니다.
1. 현재 사용 중인 Ubuntu 버전에 대한 Linux 패키지를 사용하여 GitLab 인스턴스를 업그레이드합니다.

### 리포지토리 디렉토리 나열 Rake 작업 {#list-repository-directories-rake-task}

- GitLab 16.7에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/384361)를 참조하세요.

`gitlab-rake gitlab:list_repos` Rake 작업이 작동하지 않으며 GitLab 17.0에서 제거될 것입니다. GitLab을 마이그레이션하는 경우 대신 [백업 및 복원](https://docs.gitlab.com/administration/operations/moving_repositories/#recommended-approach-in-all-cases)을 사용하세요.

### GraphQL API를 사용하여 패키지 설정을 변경할 수 있는 유지 관리자 역할 {#maintainer-role-providing-the-ability-to-change-package-settings-using-graphql-api}

- GitLab 15.8에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/370471)를 참조하세요.

GraphQL API를 사용하여 그룹의 **패키지 및 레지스트리** 설정을 변경할 수 있는 유지 관리자 역할이 있는 사용자의 능력은 GitLab 15.8에서 사용 중단되었으며 GitLab 17.0에서 제거될 것입니다. 이 설정에는:

- [중복 패키지 업로드 허용 또는 방지](https://docs.gitlab.com/user/packages/maven_repository/#do-not-allow-duplicate-maven-packages).
- [패키지 요청 전달](https://docs.gitlab.com/user/packages/maven_repository/#request-forwarding-to-maven-central).
- [종속성 프록시에 대한 수명 주기 규칙 활성화](https://docs.gitlab.com/user/packages/dependency_proxy/reduce_dependency_proxy_storage/).

GitLab 17.0 이상에서는 GitLab UI 또는 GraphQL API를 사용하여 그룹의 **패키지 및 레지스트리** 설정을 변경하려면 소유자 역할을 가져야 합니다.

### 종속성 검사 및 라이선스 검사에서 Maven 버전 3.8.8 이하 지원 {#maven-versions-below-388-support-in-dependency-scanning-and-license-scanning}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/438772)를 참조하세요.

GitLab 17.0은 Maven 버전 3.8.8 이하에 대한 종속성 검사 및 라이선스 검사 지원을 중단합니다.

사용자는 3.8.8 이상으로 업그레이드할 것을 권장합니다.

### Sidekiq 옵션의 최소 동시성 및 최대 동시성 {#min-concurrency-and-max-concurrency-in-sidekiq-options}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/439687)를 참조하세요.

Linux 패키지(Omnibus) 설치의 경우 [`sidekiq['min_concurrency']` 및 `sidekiq['max_concurrency']` 설정은 GitLab 16.9에서 사용 중단되었으며 GitLab 17.0에서 제거될 것입니다.](https://docs.gitlab.com/administration/sidekiq/extra_sidekiq_processes/#manage-thread-counts-explicitly)

GitLab 16.9 이상에서 `sidekiq['concurrency']`을 사용하여 각 프로세스의 스레드 수를 명시적으로 설정할 수 있습니다.

위의 변경 사항은 Linux 패키지(Omnibus) 설치에만 적용됩니다.

GitLab Helm 차트 설치의 경우 `SIDEKIQ_CONCURRENCY_MIN` 및/또는 `SIDEKIQ_CONCURRENCY_MAX`을 `extraEnv`으로 `sidekiq` 부차트에 전달하는 것은 GitLab 16.10에서 사용 중단되었으며 GitLab 17.0에서 제거될 것입니다.

각 프로세스의 스레드 수를 명시적으로 설정하려면 `concurrency` 옵션을 사용할 수 있습니다.

### `/users` REST API 엔드포인트의 오프셋 페이지 매김 사용 중단 {#offset-pagination-for-users-rest-api-endpoint-is-deprecated}

- GitLab 16.5에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/426547)를 참조하세요.

`/users` REST API의 오프셋 페이지 매김은 GitLab 16.5에서 사용 중단되었으며 GitLab 17.0에서 제거될 것입니다. 대신 [키셋 페이지 매김](https://docs.gitlab.com/api/rest/#keyset-based-pagination)을 사용하세요.

### 이전 JSON 웹 토큰 버전은 사용 중단됨 {#old-versions-of-json-web-tokens-are-deprecated}

- GitLab 15.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/366798)를 참조하세요.

[ID 토큰](https://docs.gitlab.com/ci/secrets/id_token_authentication/)과 OIDC 지원은 GitLab 15.7에서 도입되었습니다. 이 토큰들은 이전 JSON 웹 토큰(JWT)보다 더 구성 가능하고 OIDC를 준수하며 ID 토큰이 명시적으로 구성된 CI/CD 작업에서만 사용 가능합니다. ID 토큰은 모든 작업에 노출되는 이전 `CI_JOB_JWT*` JSON 웹 토큰보다 더 안전하므로 이 이전 JSON 웹 토큰들은 사용 중단됩니다:

- `CI_JOB_JWT`
- `CI_JOB_JWT_V1`
- `CI_JOB_JWT_V2`

이 변경을 준비하려면 사용 중단된 토큰 대신 [ID 토큰](https://docs.gitlab.com/ci/yaml/#id_tokens)을 사용하도록 파이프라인을 구성하세요. OIDC 준수를 위해 `iss` 청구는 이제 완전한 도메인 이름(예: `https://example.com`)을 사용합니다. 이전에는 `CI_JOB_JWT_V2` 토큰과 함께 도입되었습니다.

GitLab 15.9~15.11에서 [**JSON 웹 토큰(JWT) 액세스 제한** 설정을 활성화](https://docs.gitlab.com/ci/secrets/id_token_authentication/#enable-automatic-id-token-authentication)할 수 있습니다. 이렇게 하면 이전 토큰이 작업에 노출되지 않고 [`secrets:vault` 키워드에 대한 ID 토큰 인증](https://docs.gitlab.com/ci/secrets/id_token_authentication/#configure-automatic-id-token-authentication)이 활성화됩니다.

GitLab 16.0 이상에서:

- 이 설정은 제거될 것입니다.
- `id_tokens` 키워드를 사용하는 CI/CD 작업은 `secrets:vault`를 사용하는 ID 토큰을 사용할 수 있으며 `CI_JOB_JWT*` 토큰이 사용 가능하지 않습니다.
- `id_tokens` 키워드를 사용하지 않는 작업은 GitLab 17.0까지 `CI_JOB_JWT*` 토큰을 계속 사용할 수 있습니다.

GitLab 17.0에서 사용 중단된 토큰이 완전히 제거되며 더 이상 CI/CD 작업에서 사용할 수 없습니다.

### OmniAuth Facebook은 사용 중단됨 {#omniauth-facebook-is-deprecated}

- GitLab 16.2에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/416000)를 참조하세요.

OmniAuth Facebook 지원은 GitLab 17.0에서 제거될 것입니다. 마지막 gem 릴리스는 2021년이었으며 현재 유지 관리되지 않습니다. 현재 사용량은 0.1% 미만입니다. OmniAuth Facebook을 사용하는 경우 지원 제거 전에 [지원되는 공급자](https://docs.gitlab.com/integration/omniauth/#supported-providers)로 전환하세요.

### API 페이로드의 패키지 파이프라인은 페이지 매김됨 {#package-pipelines-in-api-payload-is-paginated}

- GitLab 14.5에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/289956)를 참조하세요.

`/api/v4/projects/:id/packages`에 대한 API 요청은 패키지의 페이지 매김된 결과를 반환합니다. 각 패키지는 이 응답에서 모든 파이프라인을 나열합니다. 이는 패키지가 수백 또는 수천 개의 연결된 파이프라인을 가질 수 있으므로 성능 문제입니다.

마일스톤 17.0에서 API 응답에서 `pipelines` 속성을 제거할 것입니다.

### PostgreSQL 13은 더 이상 지원되지 않음 {#postgresql-13-no-longer-supported}

- GitLab 16.0에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/groups/gitlab-org/-/epics/9065)를 참조하세요.

GitLab은 PostgreSQL에 대해 [연간 업그레이드 주기](https://handbook.gitlab.com/handbook/engineering/data-engineering/database-excellence/database-frameworks/postgresql-upgrade-cadence/)를 따릅니다.

PostgreSQL 13 지원은 GitLab 17.0에서 제거될 예정입니다. GitLab 17.0에서 PostgreSQL 14는 최소 필수 PostgreSQL 버전이 됩니다.

PostgreSQL 13은 전체 GitLab 16 릴리스 주기 동안 지원될 것입니다. PostgreSQL 14는 GitLab 17.0 이전에 업그레이드하려는 인스턴스에서도 지원될 것입니다. Omnibus Linux 패키지를 사용하여 설치한 단일 PostgreSQL 인스턴스를 실행 중인 경우 16.11에서 자동 업그레이드를 시도할 수 있습니다. 업그레이드를 수용할 충분한 디스크 공간이 있는지 확인하세요. 자세한 내용은 [Omnibus 데이터베이스 설명서](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server)를 참조하세요.

### 프록시 기반 DAST 사용 중단됨 {#proxy-based-dast-deprecated}

- GitLab 16.6에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/430966)를 참조하세요.

GitLab 17.0부터 프록시 기반 DAST는 지원되지 않습니다. 브라우저 기반 DAST로 마이그레이션하여 동적 분석을 통해 보안 발견을 위해 프로젝트를 계속 분석하세요. 프록시 기반 DAST 위에 구축된 **침해 및 공격 시뮬레이션**(배양 기능)도 이 사용 중단에 포함되며 17.0 이후에는 지원되지 않을 것입니다.

### Sidekiq용 큐 선택기가 더 이상 사용되지 않습니다 {#queue-selector-for-running-sidekiq-is-deprecated}

- GitLab 15.9에서 발표
- GitLab 16.0에서 지원 종료
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/390787)를 참조하세요.

[큐 선택기](https://docs.gitlab.com/administration/sidekiq/processing_specific_job_classes/#queue-selectors) (여러 프로세스가 큐 집합을 수신)를 사용하여 Sidekiq를 실행하고 [설정 무효화](https://docs.gitlab.com/administration/sidekiq/processing_specific_job_classes/#negate-settings)하는 것은 더 이상 사용되지 않으며 17.0에서 완전히 제거될 예정입니다.

큐 선택기에서 [모든 프로세스의 모든 큐 수신](https://docs.gitlab.com/administration/sidekiq/extra_sidekiq_processes/#start-multiple-processes)으로 마이그레이션할 수 있습니다. 예를 들어, Sidekiq이 현재 `sidekiq['queue_groups']` (in `/etc/gitlab/gitlab.rb`에서 4개 요소로 표시됨)의 4개 프로세스로 실행 중이고 큐 선택기(`sidekiq['queue_selector'] = true`)를 사용하는 경우, Sidekiq을 변경하여 모든 4개 프로세스의 모든 큐를 수신할 수 있습니다(예: `sidekiq['queue_groups'] = ['*'] * 4`). 이 접근 방식은 또한 [참조 아키텍처](https://docs.gitlab.com/administration/reference_architectures/5k_users/#configure-sidekiq)에서 권장됩니다. Sidekiq은 효과적으로 머신의 CPU 수만큼 많은 프로세스를 실행할 수 있습니다.

위의 접근 방식이 대부분의 인스턴스에 권장되지만, Sidekiq은 또한 GitLab.com에서도 사용 중인 [라우팅 규칙](https://docs.gitlab.com/administration/sidekiq/processing_specific_job_classes/#routing-rules)을 사용하여 실행할 수 있습니다. [큐 선택기에서 라우팅 규칙으로의 마이그레이션 가이드](https://docs.gitlab.com/administration/sidekiq/processing_specific_job_classes/#migrating-from-queue-selectors-to-routing-rules)를 따를 수 있습니다. 작업을 완전히 잃지 않도록 마이그레이션 시 주의해야 합니다.

### Linux의 작은 GitLab.com 러너에서 태그 제거 {#removal-of-tags-from-small-gitlabcom-runners-on-linux}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab-runner/-/issues/30829)를 참조하세요.

역사적 이유로 인해 작은 Linux GitLab.com 러너에는 레이블로 사용되었기 때문에 많은 태그가 연결되어 있었습니다. `saas-linux-small-amd64`만 사용하도록 태그를 간소화하고 모든 GitLab.com 러너에서 일관되게 유지하려고 합니다.

다음 태그를 지원 중단하고 있습니다: `docker`, `east-c`, `gce`, `git-annex`, `linux`, `mongo`, `mysql`, `postgres`, `ruby`, `shared`.

자세한 내용은 [Linux의 작은 SaaS 러너에서 태그 제거](https://about.gitlab.com/blog/removing-tags-from-small-saas-runner-on-linux/)를 참조하세요.

### 필수 파이프라인 구성이 더 이상 사용되지 않습니다 {#required-pipeline-configuration-is-deprecated}

- GitLab 15.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/389467)를 참조하세요.

필수 파이프라인 구성은 GitLab 17.0에서 제거될 예정입니다. 이는 Ultimate 티어의 GitLab Self-Managed 사용자에게 영향을 미칩니다.

필수 파이프라인 구성을 다음 중 하나로 바꾸어야 합니다:

- 실험적인 [규정 준수 프레임워크 범위가 지정된 보안 정책](https://docs.gitlab.com/user/application_security/policies/scan_execution_policies/#security-policy-scopes).
- 현재 사용 가능한 [규정 준수 파이프라인](https://docs.gitlab.com/user/group/compliance_pipelines/).

필수 파이프라인을 특정 규정 준수 프레임워크 레이블에 할당할 수 있도록 하여 더 큰 유연성을 제공하므로 이러한 대체 솔루션을 권장합니다.

규정 준수 파이프라인은 향후 지원 중단될 것이며 보안 정책으로 마이그레이션될 것입니다. 자세한 내용은 [마이그레이션 및 지원 중단 에픽](https://gitlab.com/groups/gitlab-org/-/epics/11275)을 참조하세요.

### GitLab 17.0에서 SAST 분석기 범위 변경 {#sast-analyzer-coverage-changing-in-gitlab-170}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/412060)를 참조하세요.

GitLab SAST에서 기본적으로 사용되는 [분석기](https://docs.gitlab.com/user/application_security/sast/analyzers/)의 수를 줄이고 있습니다. 이는 다양한 프로그래밍 언어에서 더 빠르고 일관된 사용자 경험을 제공하려는 장기 전략의 일부입니다.

GitLab 17.0에서 다음을 수행합니다:

1. [SAST CI/CD 템플릿](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/SAST.gitlab-ci.yml)에서 언어별 분석기 집합을 제거하고 [Semgrep 기반 분석기](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep)의 [GitLab 지원 검출 규칙](https://docs.gitlab.com/user/application_security/sast/rules/)으로 해당 범위를 바꿉니다. 다음 분석기는 현재 지원 중단되었으며 GitLab 17.0에서 지원 종료에 도달합니다:
   1. [Brakeman](https://gitlab.com/gitlab-org/security-products/analyzers/brakeman) (Ruby, Ruby on Rails)
   1. [Flawfinder](https://gitlab.com/gitlab-org/security-products/analyzers/flawfinder) (C, C++)
   1. [MobSF](https://gitlab.com/gitlab-org/security-products/analyzers/mobsf) (Android, iOS)
   1. [NodeJS Scan](https://gitlab.com/gitlab-org/security-products/analyzers/nodejs-scan) (Node.js)
   1. [PHPCS Security Audit](https://gitlab.com/gitlab-org/security-products/analyzers/phpcs-security-audit) (PHP)
1. [SAST CI/CD 템플릿](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/SAST.gitlab-ci.yml)을 변경하여 Kotlin 및 Scala 코드에 대해 [SpotBugs 기반 분석기](https://gitlab.com/gitlab-org/security-products/analyzers/spotbugs) 실행을 중지합니다. 이러한 언어는 대신 [Semgrep 기반 분석기](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep)의 [GitLab 지원 검출 규칙](https://docs.gitlab.com/user/application_security/sast/rules/)을 사용하여 스캔됩니다.

즉시 적용되는 지원 중단된 분석기는 보안 업데이트만 받습니다. 다른 정기적인 개선 사항이나 업데이트는 보장되지 않습니다. 분석기가 GitLab 17.0에서 지원 종료에 도달한 후에는 추가 업데이트가 제공되지 않습니다. 그러나 이러한 분석기에 대해 이전에 게시된 컨테이너 이미지를 삭제하거나 사용자 지정 CI/CD 파이프라인 작업 정의를 사용하여 실행할 수 있는 기능을 제거하지 않습니다.

취약성 관리 시스템은 대부분의 기존 검결을 업데이트하여 새 검출 규칙과 일치하도록 합니다. 새 분석기로 마이그레이션되지 않은 검결은 [자동으로 해결됩니다](https://docs.gitlab.com/user/application_security/sast/#automatic-vulnerability-resolution). [취약성 변환 문서](https://docs.gitlab.com/user/application_security/sast/analyzers/#vulnerability-translation)를 참조하여 자세한 내용을 알아보세요.

제거된 분석기에 대한 사용자 지정을 적용했거나 현재 파이프라인에서 Semgrep 기반 분석기를 비활성화한 경우, [이 변경을 위한 지원 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/412060#action-required)에 자세히 설명된 대로 조치를 취해야 합니다.

### `_EXCLUDED_ANALYZERS` 변수를 사용한 검사 실행 정책이 프로젝트 변수를 재정의합니다 {#scan-execution-policies-using-_excluded_analyzers-variable-override-project-variables}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/424513)를 참조하세요.

[SEP 변수를 가장 높은 우선순위로 적용](https://gitlab.com/gitlab-org/gitlab/-/issues/424028)을 전달하고 확인한 후, 사용자가 파이프라인 구성에서 `_EXCLUDED_PATHS`를 설정하고 정책과 파이프라인 구성 모두에서 `_EXCLUDED_ANALYZERS`를 설정하지 못하게 하는 의도하지 않은 동작을 발견했습니다.

검사 실행 변수의 적절한 적용을 보장하기 위해, GitLab 검사 작업을 사용하는 검사 실행 정책에 `_EXCLUDED_ANALYZERS` 또는 `_EXCLUDED_PATHS` 변수를 지정하면, 변수가 제외된 분석기에 대해 정의된 프로젝트 변수를 재정의합니다.

사용자는 17.0 이전에 이 동작을 적용하려면 기능 플래그를 활성화할 수 있습니다. 17.0에서 변수가 정의된 검사 실행 정책을 사용하는 `_EXCLUDED_ANALYZERS`/`_EXCLUDED_PATHS` 변수를 활용하는 프로젝트는 기본적으로 재정의됩니다.

### 보안 분석기 주요 버전 업데이트 {#secure-analyzers-major-version-update}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/438123)를 참조하세요.

보안 단계는 GitLab 17.0 릴리스와 함께 분석기의 주요 버전을 함께 올릴 것입니다.

기본 포함 템플릿을 사용하지 않거나 분석기 버전을 고정한 경우, CI/CD 작업 정의를 업데이트하여 고정된 버전을 제거하거나 최신 주요 버전으로 업데이트해야 합니다.

GitLab 16.0-16.11의 사용자는 GitLab 17.0 출시 때까지 정상적으로 분석기 업데이트를 계속 받을 것이며, 이후 새로운 주요 버전의 분석기에서만 새로운 버그 수정과 출시된 기능이 제공됩니다.

유지 관리 정책에 따라 더 이상 사용되지 않는 버전의 버그 및 기능을 백포트하지 않습니다. 필요에 따라 최신 3개의 부 릴리스 내에서 보안 패치가 백포트됩니다.

특히 다음 분석기는 지원 중단되며 GitLab 17.0 릴리스 후에는 더 이상 업데이트되지 않습니다:

- 컨테이너 스캔: 버전 6
- 종속성 검사: 버전 4
- DAST: 버전 4
- DAST API: 버전 3
- Fuzz API: 버전 3
- IaC 스캔: 버전 4
- 시크릿 검색: 버전 5
- 정적 애플리케이션 보안 테스트(SAST): [모든 분석기](https://docs.gitlab.com/user/application_security/sast/analyzers/) 버전 4
  - `brakeman`
  - `flawfinder`
  - `kubesec`
  - `mobsf`
  - `nodejs-scan`
  - `phpcs-security-audit`
  - `pmd-apex`
  - `semgrep`
  - `sobelow`
  - `spotbugs`

### 보안 정책 필드 `match_on_inclusion`는 더 이상 사용되지 않습니다 {#security-policy-field-match_on_inclusion-is-deprecated}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/424513)를 참조하세요.

[검사 결과 정책에 대한 추가 필터 지원](https://gitlab.com/groups/gitlab-org/-/epics/6826#note_1341377224)에서 `newly_detected` 필드를 두 가지 옵션으로 나누었습니다: `new_needs_triage` 및 `new_dismissed`. 보안 정책 YAML에 두 가지 옵션을 모두 포함하면 원래 `newly_detected` 필드와 동일한 결과를 얻을 수 있습니다. 그러나 이제 `new_needs_triage`만 사용하여 필터를 좁혀 해제된 검결을 무시할 수 있습니다. [에픽 10203](https://gitlab.com/groups/gitlab-org/-/epics/10203#note_1545826313)의 논의를 바탕으로, YAML 정의의 명확성을 위해 `match_on_inclusion` 필드의 이름을 `match_on_inclusion_license`로 변경했습니다.

### 보안 정책 필드 `newly_detected`는 더 이상 사용되지 않습니다 {#security-policy-field-newly_detected-is-deprecated}

- GitLab 16.5에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/422414)를 참조하세요.

[검사 결과 정책에 대한 추가 필터 지원](https://gitlab.com/groups/gitlab-org/-/epics/6826#note_1341377224)에서 `newly_detected` 필드를 두 가지 옵션으로 나누었습니다: `new_needs_triage` 및 `new_dismissed`. 보안 정책 YAML에 두 가지 옵션을 모두 포함하면 원래 `newly_detected` 필드와 동일한 결과를 얻을 수 있습니다. 그러나 이제 `new_needs_triage`만 사용하여 필터를 좁혀 해제된 검결을 무시할 수 있습니다.

### 자체 호스팅 Sentry 버전 21.4.1 이상에 대한 지원 {#support-for-self-hosted-sentry-versions-2141-and-earlier}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/435791)를 참조하세요.

자체 호스팅 Sentry 버전 21.4.1 이상에 대한 지원은 지원 중단되며 GitLab 17.0에서 제거됩니다.

자체 호스팅 Sentry 버전이 21.4.1 이상인 경우, GitLab 17.0 이상으로 업그레이드한 후 GitLab 인스턴스에서 오류를 수집하지 못할 수 있습니다. GitLab 인스턴스에서 Sentry 인스턴스로 계속 오류를 보내려면 Sentry를 버전 21.5.0 이상으로 업그레이드하세요. 자세한 내용은 [Sentry 문서](https://develop.sentry.dev/self-hosted/releases/)를 참조하세요.

> [!note]
> 지원 중단된 지원은 관리자를 위한 [GitLab 인스턴스 오류 추적 기능](https://docs.gitlab.com/omnibus/settings/configuration/#error-reporting-and-logging-with-sentry)을 대상으로 합니다. 지원 중단된 지원은 개발자 자신의 배포된 애플리케이션을 위한 [GitLab 오류 추적](https://docs.gitlab.com/operations/error_tracking/#sentry-error-tracking)과 관련이 없습니다.

### 백업을 위한 사용자 지정 스키마 설정에 대한 지원이 더 이상 사용되지 않습니다 {#support-for-setting-custom-schema-for-backup-is-deprecated}

- GitLab 16.8에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/435210)를 참조하세요.

Linux 패키지 설치의 경우 `/etc/gitlab/gitlab.rb`에서 `gitlab_rails['backup_pg_schema'] = '<schema_name>'`를 설정하여 백업을 위해 사용자 지정 스키마를 사용하도록 GitLab을 구성하거나, 자체 컴파일 설치의 경우 `config/gitlab.yml`을 편집할 수 있습니다.

구성 설정이 사용 가능했지만 아무 영향을 주지 않았으며 의도된 목적을 수행하지 않았습니다. 이 구성 설정은 GitLab 17.0에서 제거될 예정입니다.

### GitHub 가져오기 Rake 작업 {#the-github-importer-rake-task}

- GitLab 16.6에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/428225)를 참조하세요.

GitLab 16.6에서 GitHub 가져오기 Rake 작업은 지원 중단되었습니다. Rake 작업에는 API에서 지원하는 여러 기능이 부족하며 적극적으로 유지 관리되지 않습니다.

GitLab 17.0에서 Rake 작업이 제거됩니다.

대신 GitHub 리포지토리를 [API](https://docs.gitlab.com/api/import/#import-repository-from-github) 또는 [UI](https://docs.gitlab.com/user/project/import/github/)를 사용하여 가져올 수 있습니다.

### 비주얼 리뷰 도구가 더 이상 사용되지 않습니다 {#the-visual-reviews-tool-is-deprecated}

- GitLab 15.8에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/387751)를 참조하세요.

제한된 고객 사용 및 기능으로 인해 검토 앱의 비주얼 리뷰 기능은 지원 중단되며 제거될 예정입니다. 계획된 대체 기능이 없으므로 사용자는 GitLab 17.0 이전에 비주얼 리뷰 사용을 중지해야 합니다.

### `gitlab-runner exec` 명령이 더 이상 사용되지 않습니다 {#the-gitlab-runner-exec-command-is-deprecated}

- GitLab 15.7에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/385235)를 참조하세요.

`gitlab-runner exec` 명령은 지원 중단되었으며 GitLab Runner 16.0에서 완전히 제거됩니다. `gitlab-runner exec` 기능은 처음에 GitLab 인스턴스에 커밋할 필요 없이 로컬 시스템에서 GitLab CI 파이프라인을 검증할 수 있는 기능을 제공하기 위해 개발되었습니다. 그러나 GitLab CI의 계속된 진화로 인해 모든 GitLab CI 기능을 `gitlab-runner exec`로 복제하는 것은 더 이상 실행 가능하지 않습니다. 파이프라인 구문 및 검증 [시뮬레이션](https://docs.gitlab.com/ci/pipeline_editor/#simulate-a-cicd-pipeline)은 GitLab 파이프라인 편집기에서 사용 가능합니다.

### GitLab 에이전트의 풀 기반 배포 기능이 Kubernetes에 대해 더 이상 사용되지 않습니다 {#the-pull-based-deployment-features-of-the-gitlab-agent-for-kubernetes-is-deprecated}

- GitLab 16.2에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/406545)를 참조하세요.

Flux 및 관련 통합을 선호하여 Kubernetes용 GitLab 에이전트의 빌트인 풀 기반 배포 기능을 지원 중단하고 있습니다.

Kubernetes용 GitLab 에이전트는 **더 이상 사용되지 않습니다**. 이 변경은 에이전트의 풀 기반 기능에만 영향을 미칩니다. 다른 모든 기능은 그대로 유지되며, GitLab은 Kubernetes용 에이전트를 계속 지원할 것입니다.

풀 기반 배포를 위해 에이전트를 사용하는 경우, [Flux로 마이그레이션](https://docs.gitlab.com/user/clusters/agent/gitops/agent/#migrate-to-flux)해야 합니다. Flux는 GitOps를 위한 성숙한 CNCF 프로젝트이므로, 2023년 2월에 [GitLab과 Flux를 통합하기로 결정](https://about.gitlab.com/blog/why-did-we-choose-to-integrate-fluxcd-with-gitlab/)했습니다.

### Twitter OmniAuth 로그인 옵션은 GitLab Self-Managed에서 더 이상 사용되지 않습니다 {#twitter-omniauth-login-option-is-deprecated-from-gitlab-self-managed}

- GitLab 16.3에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-com/Product/-/issues/11417)를 참조하세요.

Twitter OAuth 1.0a OmniAuth는 지원 중단되며 사용량 부족 및 gem 지원 부족으로 인해 GitLab 17.0에서 GitLab Self-Managed용으로 제거됩니다. [지원되는 다른 OmniAuth 제공자](https://docs.gitlab.com/integration/omniauth/#supported-providers)를 대신 사용하세요.

### 통합 승인 규칙이 더 이상 사용되지 않습니다 {#unified-approval-rules-are-deprecated}

- GitLab 16.1에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/groups/gitlab-org/-/epics/9662)를 참조하세요.

통합 승인 규칙은 더 큰 유연성을 제공하는 여러 승인 규칙을 선호하여 지원 중단됩니다. 통합 승인 규칙을 여러 승인 규칙으로 마이그레이션하지 못할 수 있습니다. 수동으로 마이그레이션하는 데 도움을 드리기 위해 마이그레이션 문서를 도입했습니다.

통합 승인 규칙이 제거되기 전에 수동으로 마이그레이션하지 않으면 GitLab이 자동으로 설정을 마이그레이션합니다. 여러 승인 규칙은 승인 규칙에 대한 더 세밀한 설정을 허용하므로, GitLab에 마이그레이션을 맡기면 자동 마이그레이션이 선호할 수 있는 것보다 더 제한적인 규칙으로 끝날 수 있습니다. 더 많은 승인이 예상되는 문제가 있는 경우 마이그레이션 규칙을 확인하세요.

GitLab 15.11에서 통합 승인 규칙에 대한 UI 지원이 제거되었습니다. API를 사용하여 통합 승인 규칙에 계속 액세스할 수 있습니다.

### Linux의 GitLab.com 러너의 운영 체제 버전 업그레이드 {#upgrading-the-operating-system-version-of-gitlabcom-runners-on-linux}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/ci-cd/shared-runners/infrastructure/-/issues/60)를 참조하세요.

GitLab은 Linux의 GitLab.com 러너에 대해 작업을 실행하는 데 사용되는 임시 VM의 컨테이너 최적화 운영 체제(COS)를 업그레이드하고 있습니다. COS 업그레이드에는 알려진 호환성 문제를 야기하는 Docker Engine을 버전 19.03.15에서 버전 23.0.5로 업그레이드하는 것이 포함됩니다.

버전 20.10 이전의 Docker-in-Docker 또는 v1.9.0보다 오래된 Kaniko 이미지는 컨테이너 런타임을 감지하지 못하고 실패합니다.

자세한 내용은 [Linux의 SaaS 러너의 운영 체제 버전 업그레이드](https://about.gitlab.com/blog/updating-the-os-version-of-saas-runners-on-linux/)를 참조하세요.

### 취약성 신뢰도 필드 {#vulnerability-confidence-field}

- GitLab 15.4에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/372332)를 참조하세요.

GitLab 15.3에서 [버전 15 이하의 보안 보고서 스키마가 지원 중단되었습니다](https://docs.gitlab.com/update/deprecations/#security-report-schemas-version-14xx). `confidence` 특성은 스키마 버전 `15-0-0` 이전에만 존재하는 취약성 검결에 있으므로, GitLab 15.4가 스키마 버전 `15-0-0`를 지원하기 때문에 사실상 더 이상 사용되지 않습니다. 보고서와 공개 API 간의 일관성을 유지하기 위해 GraphQL API의 취약성 관련 구성 요소의 `confidence` 특성은 이제 더 이상 사용되지 않으며 17.0에서 제거될 예정입니다.

### `after_script` 키워드는 취소된 작업에 대해 실행됩니다 {#after_script-keyword-will-run-for-canceled-jobs}

- GitLab 16.8에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/437789)를 참조하세요.

[`after_script`](https://docs.gitlab.com/ci/yaml/#after_script) CI/CD 키워드는 작업의 주요 `script` 섹션 이후에 추가 명령을 실행하는 데 사용됩니다. 이는 종종 작업에서 사용한 환경 또는 기타 리소스를 정리하는 데 사용됩니다. 많은 사용자의 경우 `after_script` 명령이 작업이 취소되면 실행되지 않는다는 사실은 예상치 못한 일이었고 바라지 않았습니다. 17.0에서는 키워드를 업데이트하여 작업 취소 후에도 명령을 실행하도록 합니다. `after_script` 키워드를 사용하는 CI/CD 구성이 취소된 작업에 대해서도 실행할 수 있는지 확인하세요.

### `dependency_files`는 더 이상 사용되지 않습니다 {#dependency_files-is-deprecated}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/396376)를 참조하세요.

현재 GitLab에서 프로젝트의 종속성 목록은 종속성 검사 보고서의 `dependency_files`에서 콘텐츠를 사용하여 생성됩니다. 그러나 그룹 종속성 목록과의 일관성을 유지하기 위해 GitLab 17.0부터 프로젝트의 종속성 목록은 PostgreSQL 데이터베이스에 저장된 CycloneDX SBOM 보고서 아티팩트를 사용합니다. 따라서 종속성 검사 보고서 스키마의 `dependency_files` 속성은 지원 중단되며 17.0에서 제거될 예정입니다.

이 지원 중단의 일부로 [`dependency_path`](https://docs.gitlab.com/user/application_security/dependency_list/#dependency-paths)도 지원 중단되며 17.0에서 제거됩니다. GitLab은 [CycloneDX 사양을 사용한 종속성 그래프](https://gitlab.com/gitlab-org/gitlab/-/issues/441118) 구현을 진행하여 유사한 정보를 제공합니다.

또한 컨테이너 검사 CI 작업은 [더 이상 종속성 검사 보고서를 생성하지 않습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/439782). 이는 CycloneDX SBOM 보고서로 대체되는 운영 체제 구성 요소 목록을 제공합니다. 컨테이너 검사용 `CS_DISABLE_DEPENDENCY_LIST` 환경 변수는 더 이상 사용되지 않으며 17.0에서도 제거됩니다.

### DORA API에 대한 `metric` 필터 및 `value` 필드 {#metric-filter-and-value-field-for-dora-api}

- GitLab 16.8에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/393172)를 참조하세요.

이제 새로운 메트릭 필드를 사용하여 여러 DORA 메트릭을 동시에 쿼리할 수 있습니다. GraphQL DORA API의 `metric` 필터와 `value` 필드는 GitLab 17.0에서 제거됩니다.

### `omniauth-azure-oauth2` gem은 더 이상 사용되지 않습니다 {#omniauth-azure-oauth2-gem-is-deprecated}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/408989)를 참조하세요.

GitLab 사용자는 `omniauth-azure-oauth2` gem을 사용하여 GitLab에 인증할 수 있습니다. 17.0에서는 이 gem이 `omniauth_openid_connect` gem으로 대체됩니다. 새 gem에는 이전 gem과 동일한 모든 기능이 포함되어 있지만 업스트림 유지 관리도 있으며 보안 및 중앙집중식 유지 관리에 더 좋습니다.

이 변경을 위해서는 사용자가 마이그레이션 시 OAuth 2.0 공급자에 다시 연결해야 합니다. 중단을 피하려면 17.0 이전에 언제든지 [`omniauth_openid_connect`을 새 공급자로 추가](https://docs.gitlab.com/administration/auth/oidc/#configure-multiple-openid-connect-providers)하세요. 사용자는 새 로그인 버튼을 보게 되며 자신의 자격 증명을 수동으로 다시 연결해야 합니다. 17.0 이전에 `omniauth_openid_connect` gem을 구현하지 않으면 사용자는 더 이상 Azure 로그인 버튼을 사용하여 로그인할 수 없으며 관리자가 올바른 gem을 구현할 때까지 사용자 이름 및 암호를 사용하여 로그인해야 합니다.

### `omnibus_gitconfig` 구성 항목이 더 이상 사용되지 않습니다 {#omnibus_gitconfig-configuration-item-is-deprecated}

- GitLab 16.10에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitaly/-/issues/5132)를 참조하세요.

`omnibus_gitconfig['system']` 구성 항목이 지원 중단되었습니다. `omnibus_gitconfig['system']`를 사용하여 Gitaly의 사용자 지정 Git 구성을 설정한 경우, GitLab 17.0으로 업그레이드하기 전에 `gitaly[:configuration][:git][:config]` 아래의 Gitaly 구성을 통해 Git을 직접 구성해야 합니다.

예를 들어:

```ruby
  gitaly[:configuration][:git][:config] = [
    {
      key: 'fetch.fsckObjects',
      value: 'true',
    },
    # ...
  ]
```

구성 키의 형식은 CLI 플래그 `git -c <configuration>`를 통해 `git`로 전달되는 내용과 일치해야 합니다.

기존 키를 예상 형식으로 변환하는 데 문제가 있으면 Gitaly의 Linux 패키지 생성 구성 파일에서 올바른 형식의 기존 키를 참조하세요. 기본적으로 구성 파일은 `/var/opt/gitlab/gitaly/config.toml`에 있습니다.

Gitaly에서 관리하는 다음 구성 옵션을 제거해야 합니다. 이러한 키는 Gitaly로 마이그레이션할 필요가 없습니다:

- `pack.threads=1`
- `receive.advertisePushOptions=true`
- `receive.fsckObjects=true`
- `repack.writeBitmaps=true`
- `transfer.hideRefs=^refs/tmp/`
- `transfer.hideRefs=^refs/keep-around/`
- `transfer.hideRefs=^refs/remotes/`
- `core.alternateRefsCommand="exit 0 #"`
- `core.fsyncObjectFiles=true`
- `fetch.writeCommitGraph=true`

### `postgres_exporter['per_table_stats']` 구성 설정 {#postgres_exporterper_table_stats-configuration-setting}

- GitLab 16.4에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8164)를 참조하세요.

Linux 패키지는 번들 PostgreSQL 내보내기 도구용 사용자 지정 쿼리를 제공하며, 여기에는 `postgres_exporter['per_table_stats']` 구성 설정으로 제어되는 `per_table_stats` 쿼리가 포함되었습니다.

PostgreSQL 내보내기 도구는 이제 동일한 메트릭을 제공하는 `stat_user_tables` 수집기를 제공합니다. `postgres_exporter['per_table_stats']`가 활성화되어 있었다면 `postgres_exporter['flags']['collector.stat_user_tables']`을 대신 활성화하세요.

### `projectFingerprint` GraphQL 필드 {#projectfingerprint-graphql-field}

- GitLab 15.1에서 발표됨
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/343475)를 참조하세요.

취약성 검결의 [`project_fingerprint`](https://gitlab.com/groups/gitlab-org/-/epics/2791) 특성은 `uuid` 특성을 선호하여 지원 중단되고 있습니다. UUIDv5 값을 사용하여 검결을 식별하면 관련 엔티티를 검결과 쉽게 연결할 수 있습니다. `project_fingerprint` 특성은 더 이상 검결 추적에 사용되지 않으며 GitLab 17.0에서 제거됩니다. 16.1부터 `project_fingerprint`의 출력은 `uuid` 필드와 동일한 값을 반환합니다.

### 공개 프로젝트에 대한 `repository_download_operation` 감사 이벤트 유형 {#repository_download_operation-audit-event-type-for-public-projects}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/383218)를 참조하세요.

감사 이벤트 유형 `repository_download_operation`는 현재 공개 프로젝트와 비공개 프로젝트 모두의 모든 프로젝트 다운로드에 대해 데이터베이스에 저장됩니다. 공개 프로젝트의 경우, 인증되지 않은 사용자가 트리거할 수 있기 때문에 이 감사 이벤트는 감사 목적에 가장 유용하지 않습니다.

GitLab 17.0부터 `repository_download_operation` 감사 이벤트 유형은 비공개 또는 내부 프로젝트에 대해서만 트리거됩니다. 공개 프로젝트 다운로드를 위해 `public_repository_download_operation`라는 새로운 감사 이벤트 유형을 추가합니다. 이 새로운 감사 이벤트 유형은 스트리밍만 합니다.

### npm 패키지 업로드는 이제 비동기적으로 발생합니다 {#npm-package-uploads-now-occur-asynchronously}

- GitLab 16.9에서 발표
- GitLab 17.0에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/433009)를 참조하세요.

GitLab 패키지 레지스트리는 npm 및 Yarn을 지원합니다. npm 또는 Yarn 패키지를 업로드하면 업로드는 동기식입니다. 그러나 동기식 업로드에는 알려진 문제가 있습니다. 예를 들어, GitLab은 [재정의](https://gitlab.com/gitlab-org/gitlab/-/issues/432876)와 같은 기능을 지원하지 않습니다.

17.0부터 npm 및 Yarn 패키지는 비동기적으로 업로드됩니다. 패키지가 게시되자마자 사용 가능할 것으로 예상하는 파이프라인이 있을 수 있으므로 이것이 주요 변경 사항입니다.

해결 방법으로 [패키지 API](https://docs.gitlab.com/api/packages/)를 사용하여 패키지를 확인해야 합니다.

## GitLab 16.9 {#gitlab-169}

### `lfs_check` 기능 플래그 지원 중단 {#deprecation-of-lfs_check-feature-flag}

- GitLab 16.6에서 발표됨
- GitLab 16.9에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/233550)를 참조하세요.

GitLab 16.9에서 `lfs_check` 기능 플래그를 제거합니다. 이 기능 플래그는 [4년 전에 도입되었으며](https://gitlab.com/gitlab-org/gitlab-foss/-/issues/60588) LFS 무결성 검사 활성화 여부를 제어합니다. 기능 플래그는 기본적으로 활성화되어 있지만 일부 고객이 LFS 무결성 검사의 성능 문제를 경험했으며 명시적으로 비활성화했습니다.

LFS 무결성 검사의 성능을 [극적으로 개선](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/61355)한 후, 기능 플래그를 제거할 준비가 되었습니다. 플래그가 제거된 후 기능은 현재 비활성화되어 있는 모든 환경에서 자동으로 활성화됩니다.

기능 플래그가 환경에 대해 비활성화되어 있고 성능 문제를 우려하는 경우, 16.9에서 제거되기 전에 활성화하고 성능을 모니터링하세요. 활성화 후 성능 문제가 발생하면 [이 피드백 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/233550)에서 알려주세요.

## GitLab 16.8 {#gitlab-168}

### openSUSE Leap 15.4 패키지 {#opensuse-leap-154-packages}

- GitLab 16.5에서 발표
- GitLab 16.8에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8212)를 참조하세요.

openSUSE Leap 15.4의 지원 및 보안 업데이트는 [2023년 11월에 종료됩니다](https://en.opensuse.org/Lifetime#openSUSE_Leap).

GitLab 15.4는 openSUSE Leap 15.5에 대한 패키지를 제공했습니다. GitLab 15.8 이상은 openSUSE Leap 15.4에 대한 패키지를 제공하지 않습니다.

GitLab 15.8 이상을 준비하려면 다음을 수행해야 합니다:

1. 인스턴스를 openSUSE Leap 15.4에서 openSUSE Leap 15.5로 이동합니다.
1. openSUSE Leap 15.4 GitLab 제공 패키지에서 openSUSE Leap 15.5 GitLab 제공 패키지로 전환합니다.

## GitLab 16.7 {#gitlab-167}

### Shimo 통합 {#shimo-integration}

- GitLab 15.7에서 발표됨
- GitLab 16.7에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/377824)를 참조하세요.

**Shimo 작업 공간 통합**은 지원 중단되었으며 JiHu GitLab 코드베이스로 이동될 예정입니다.

### `user_email_lookup_limit` API 필드 {#user_email_lookup_limit-api-field}

- GitLab 14.9에서 발표됨
- GitLab 16.7에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))

`user_email_lookup_limit` [API 필드](https://docs.gitlab.com/api/settings/)는 GitLab 14.9에서 지원 중단되었으며 GitLab 16.7에서 제거됩니다. 기능이 제거될 때까지 `user_email_lookup_limit`은 `search_rate_limit`의 별칭이며 기존 워크플로는 계속 작동합니다.

`user_email_lookup_limit`의 속도 제한을 변경하려는 모든 API 호출은 `search_rate_limit`을 대신 사용해야 합니다.

## GitLab 16.6 {#gitlab-166}

### 작업 토큰 허용 목록이 공개 및 내부 프로젝트를 포함합니다 {#job-token-allowlist-covers-public-and-internal-projects}

- GitLab 16.3에서 발표됨
- GitLab 16.6에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/420678)를 참조하세요.

16.6부터 **공개** 또는 **내부**인 프로젝트는 [**이 프로젝트에 대한 액세스 제한**](https://docs.gitlab.com/ci/jobs/ci_job_token/#add-a-group-or-project-to-the-job-token-allowlist)이 활성화되어 있을 때 프로젝트의 허용 목록에 없는 프로젝트의 작업 토큰 요청을 더 이상 승인하지 않습니다.

[공개 또는 내부](https://docs.gitlab.com/user/public_access/#change-project-visibility) 프로젝트가 **이 프로젝트에 대한 액세스 제한** 설정이 활성화되어 있는 경우, 계속 승인을 위해 작업 토큰을 요청하는 프로젝트를 프로젝트의 허용 목록에 추가해야 합니다.

## GitLab 16.5 {#gitlab-165}

### 잠긴 LDAP 그룹에 LDAP 동기화되지 않은 구성원 추가가 더 이상 사용되지 않습니다 {#adding-non-ldap-synced-members-to-a-locked-ldap-group-is-deprecated}

- GitLab 16.0에서 발표
- GitLab 16.5에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/213311)를 참조하세요.

`ldap_settings_unlock_groups_by_owners` 기능 플래그를 활성화하면 LDAP 동기화되지 않은 사용자를 잠긴 LDAP 그룹에 추가할 수 있습니다. 이 [기능](https://gitlab.com/gitlab-org/gitlab/-/issues/1793)은 항상 기본적으로 비활성화되어 있고 기능 플래그 뒤에 있습니다. SAML 통합과의 연속성을 유지하고 동기화되지 않은 그룹 구성원 허용이 디렉터리 서비스 사용의 "단일 진실 공급원" 원칙을 무효화하기 때문에 이 기능을 제거하고 있습니다. 이 기능이 제거되면 LDAP과 동기화되지 않은 LDAP 그룹 구성원이 해당 그룹에 대한 액세스를 잃게 됩니다.

### Geo: 하우스키핑 Rake 작업 {#geo-housekeeping-rake-tasks}

- GitLab 16.3에서 발표됨
- GitLab 16.5에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/416384)를 참조하세요.

[Geo 자체 서비스 프레임워크(SSF)](https://docs.gitlab.com/development/geo/framework/)로의 복제 및 검증 마이그레이션의 일부로 프로젝트 리포지토리의 레거시 복제가 [제거되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/130565). 결과적으로, 레거시 코드에 의존하던 다음 Rake 작업도 제거되었습니다. 이러한 Rake 작업에서 호출한 작업은 이제 정기적으로 또는 트리거 이벤트를 기반으로 자동으로 트리거됩니다.

| Rake 작업 | 대체 |
| --------- | ----------- |
| `geo:git:housekeeping:full_repack` | [UI로 이동](https://docs.gitlab.com/administration/housekeeping/#heuristical-housekeeping). SSF에서 동등한 Rake 작업이 없습니다. |
| `geo:git:housekeeping:gc` | 항상 새 리포지토리에 대해 실행되고 필요할 때 실행됩니다. SSF에서 동등한 Rake 작업이 없습니다. |
| `geo:git:housekeeping:incremental_repack` | 필요할 때 실행됩니다. SSF에서 동등한 Rake 작업이 없습니다. |
| `geo:run_orphaned_project_registry_cleaner` | 고아 레지스트리를 제거하는 레지스트리 [일관성 워커](https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/app/workers/geo/secondary/registry_consistency_worker.rb)에 의해 정기적으로 실행됩니다. SSF에서 동등한 Rake 작업이 없습니다. |
| `geo:verification:repository:reset` | UI로 이동했습니다. SSF에서 동등한 Rake 작업이 없습니다. |
| `geo:verification:wiki:reset` | UI로 이동했습니다. SSF에서 동등한 Rake 작업이 없습니다. |

## GitLab 16.3 {#gitlab-163}

### 번들 Grafana가 지원 중단되고 비활성화됨 {#bundled-grafana-deprecated-and-disabled}

- GitLab 16.0에서 발표
- GitLab 16.3에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/7772)를 참조하세요.

Omnibus GitLab과 함께 번들된 Grafana의 버전은 16.0에서 [지원 중단되고 비활성화되며](https://docs.gitlab.com/administration/monitoring/performance/grafana_configuration/#deprecation-of-bundled-grafana) 16.3에서 제거될 예정입니다. 번들 Grafana를 사용하는 경우 다음 중 하나로 마이그레이션해야 합니다:

- Grafana의 다른 구현. 자세한 내용은 [새 Grafana 인스턴스로 전환](https://docs.gitlab.com/administration/monitoring/performance/grafana_configuration/#switch-to-new-grafana-instance)을 참조하세요.
- 선택한 다른 관찰성 플랫폼.

현재 제공되는 Grafana 버전은 더 이상 지원되는 버전이 아닙니다.

GitLab 버전 16.0~16.2에서 [번들 Grafana를 다시 활성화](https://docs.gitlab.com/administration/monitoring/performance/grafana_configuration/#temporary-workaround)할 수 있습니다. 그러나 번들 Grafana를 활성화하는 것은 GitLab 16.3부터 더 이상 작동하지 않습니다.

### RSA 키 크기 제한 {#rsa-key-size-limits}

- GitLab 16.3에서 발표됨
- GitLab 16.3에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/groups/gitlab-org/-/epics/11186)를 참조하세요.

Go 버전 1.20.7 이상은 RSA 키를 최대 8192비트로 제한하는 `maxRSAKeySize` 상수를 추가합니다. 결과적으로 8192비트보다 큰 RSA 키는 더 이상 GitLab에서 작동하지 않습니다. 8192비트보다 큰 모든 RSA 키는 더 작은 크기로 다시 생성해야 합니다.

로그에 `tls: server sent certificate containing RSA key larger than 8192 bits`과 같은 오류가 포함되어 있으면 이 문제를 알아차릴 수 있습니다. 키의 길이를 테스트하려면 이 명령을 사용하세요: `openssl rsa -in <your-key-file> -text -noout | grep "Key:"`.

### Twitter OmniAuth 로그인 옵션이 GitLab.com에서 제거됩니다 {#twitter-omniauth-login-option-is-removed-from-gitlabcom}

- GitLab 16.3에서 발표됨
- GitLab 16.3에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-com/Product/-/issues/11417)를 참조하세요.

Twitter OAuth 1.0a OmniAuth는 사용량 부족, gem 지원 부족, 이 기능에 대한 기능 로그인 옵션이 없어서 GitLab 16.3에서 GitLab.com에서 지원 중단되고 제거되고 있습니다. Twitter로 GitLab.com에 로그인하면 암호 또는 다른 [지원되는 OmniAuth 공급자](https://gitlab.com/users/sign_in)로 로그인할 수 있습니다.

### 라이센스 규정 준수 CI 템플릿 {#license-compliance-ci-template}

- GitLab 15.9에서 발표
- GitLab 16.3에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/387561)를 참조하세요.

**업데이트**: 이전에 기존 라이센스 규정 준수 CI/CD 템플릿을 GitLab 16.0에서 제거할 것이라고 발표했습니다. 그러나 [CycloneDX 파일의 라이센스 스캔](https://docs.gitlab.com/user/compliance/license_scanning_of_cyclonedx_files/) 성능 문제로 인해 대신 16.3에서 수행하겠습니다.

GitLab [라이센스 규정 준수](https://docs.gitlab.com/user/compliance/license_approval_policies/) CI/CD 템플릿은 이제 지원 중단되었으며 GitLab 16.3 릴리스에서 제거될 예정입니다.

라이센스 규정 준수를 계속 사용하려면 CI/CD 파이프라인에서 라이센스 규정 준수 템플릿을 제거하고 종속성 검사 템플릿을 추가하세요. 종속성 검사 템플릿은 이제 필요한 라이센스 정보를 수집할 수 있으므로 더 이상 별도의 라이센스 규정 준수 작업을 실행할 필요가 없습니다.

라이센스 규정 준수 템플릿을 제거하기 전에 인스턴스가 새 라이센스 스캔 방법을 지원하는 버전으로 업그레이드되었는지 확인하세요.

종속성 검사를 빠르게 대규모로 시작하려면 그룹 수준에서 검사 실행 정책을 설정하여 그룹의 모든 프로젝트에 대해 SBOM 기반 라이센스 검사를 적용할 수 있습니다. 그러면 CI/CD 구성에서 `Jobs/License-Scanning.gitlab-ci.yml` 템플릿의 포함을 제거할 수 있습니다.

레거시 라이센스 규정 준수 기능을 계속 사용하려면 `LICENSE_MANAGEMENT_VERSION CI` 변수를 `4`로 설정하면 됩니다. 이 변수는 프로젝트, 그룹 또는 인스턴스 수준에서 설정할 수 있습니다. 이 구성 변경을 통해 새로운 접근 방식을 채택하지 않고도 기존 버전의 라이센스 규정 준수를 계속 사용할 수 있습니다.

이 레거시 분석기의 버그 및 취약성은 더 이상 수정되지 않습니다.

| CI 파이프라인 포함 | GitLab <= 15.8 | 15.9 <= GitLab < 16.3 | GitLab >= 16.3 |
| ------------- | ------------- | ------------- | ------------- |
| DS 및 LS 템플릿 모두 | LS 작업의 라이센스 데이터가 사용됨 | LS 작업의 라이센스 데이터가 사용됨 | DS 작업의 라이센스 데이터가 사용됨 |
| DS 템플릿이 포함되었지만 LS 템플릿은 포함되지 않음 | 라이센스 데이터 없음 | DS 작업의 라이센스 데이터가 사용됨 | DS 작업의 라이센스 데이터가 사용됨 |
| LS 템플릿이 포함되었지만 DS 템플릿은 포함되지 않음 | LS 작업의 라이센스 데이터가 사용됨 | LS 작업의 라이센스 데이터가 사용됨 | 라이센스 데이터 없음 |

## GitLab 16.1 {#gitlab-161}

### Alpine 3.12, 3.13, 3.14를 기반으로 한 GitLab Runner 이미지 {#gitlab-runner-images-based-on-alpine-312-313-314}

- GitLab 15.11에서 발표됨
- GitLab 16.1에서 지원 종료
- GitLab 16.1에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab-runner/-/issues/29639)를 참조하세요.

다음의 수명이 종료된 Alpine 버전을 기반으로 하는 러너 이미지 게시를 중단합니다:

- Alpine 3.12
- Alpine 3.13
- Alpine 3.14 (2023-05-23에 수명 종료)

## GitLab 16.0 {#gitlab-160}

### 자동 DevOps는 더 이상 기본적으로 PostgreSQL 데이터베이스를 프로비저닝하지 않습니다 {#auto-devops-no-longer-provisions-a-postgresql-database-by-default}

- GitLab 15.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/343988)를 참조하세요.

현재 자동 DevOps는 기본적으로 클러스터 내 PostgreSQL 데이터베이스를 프로비저닝합니다. GitLab 16.0에서는 데이터베이스가 옵트인 사용자에게만 프로비저닝됩니다. 이 변경은 더 강력한 데이터베이스 관리가 필요한 프로덕션 배포를 지원합니다.

자동 DevOps가 클러스터 내 데이터베이스를 프로비저닝하도록 하려면 `POSTGRES_ENABLED` CI/CD 변수를 `true`로 설정하세요.

### Azure Storage 드라이버는 올바른 루트 접두사로 기본값 설정됩니다 {#azure-storage-driver-defaults-to-the-correct-root-prefix}

- GitLab 15.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/container-registry/-/issues/854)를 참조하세요.

컨테이너 레지스트리의 Azure Storage 드라이버는 `//`을 기본 루트 디렉터리로 작성합니다. 이 기본 루트 디렉터리는 Azure UI의 일부 위치에 `/<no-name>/`로 나타납니다. 이 저장소 드라이버를 사용하는 더 오래된 배포를 지원하기 위해 이 레거시 동작을 유지했습니다. 그러나 다른 저장소 드라이버에서 Azure로 이동할 때 이 동작은 `trimlegacyrootprefix: true`을 설정하여 저장소 드라이버가 루트 경로를 구축하지 않도록 구성할 때까지 모든 데이터를 숨깁니다.

저장소 드라이버의 새 기본 구성은 `trimlegacyrootprefix: true`을 설정하며, `/`는 기본 루트 디렉터리입니다. 현재 구성에 `trimlegacyrootprefix: false`을 추가하여 중단을 피할 수 있습니다.

이 주요 변경은 GitLab 16.0에서 발생합니다.

### 번들 Grafana Helm Chart가 지원 중단됩니다 {#bundled-grafana-helm-chart-is-deprecated}

- GitLab 15.10에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/4353)를 참조하세요.

GitLab Helm Chart와 번들된 Grafana Helm Chart는 GitLab Helm Chart 7.0 릴리스(GitLab 16.0과 함께 출시)에서 지원 중단되고 제거됩니다.

번들 Grafana Helm Chart는 GitLab Helm Chart의 Prometheus 메트릭에 연결된 Grafana UI를 제공하도록 켤 수 있는 선택적 서비스입니다.

GitLab Helm Chart가 현재 제공하는 Grafana 버전은 더 이상 지원되는 Grafana 버전이 아닙니다. 번들 Grafana를 사용하는 경우 [Grafana Labs의 최신 차트 버전](https://artifacthub.io/packages/helm/grafana/grafana) 또는 신뢰할 수 있는 제공자의 Grafana Operator로 전환해야 합니다.

새 Grafana 인스턴스에서 [GitLab 제공 Prometheus를 데이터 소스로 구성](https://docs.gitlab.com/administration/monitoring/performance/grafana_configuration/#configure-grafana)하고 [Grafana를 GitLab UI에 연결](https://docs.gitlab.com/administration/monitoring/performance/grafana_configuration/#integrate-with-gitlab-ui)할 수 있습니다.

### CAS OmniAuth 공급자 {#cas-omniauth-provider}

- GitLab 15.3에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/369127)를 참조하세요.

GitLab에 CAS OmniAuth 공급자를 제공하는 `omniauth-cas3` gem은 다음 주요 릴리스인 GitLab 16.0에서 제거될 예정입니다. 이 gem은 사용량이 매우 적으며 업스트림 유지 관리 부족으로 인해 GitLab이 [OmniAuth 2.0으로 업그레이드](https://gitlab.com/gitlab-org/gitlab/-/issues/30073)하지 못하고 있습니다.

### HashiCorp Vault에서 시크릿이 반환되지 않으면 CI/CD 작업이 실패합니다 {#cicd-jobs-will-fail-when-no-secret-is-returned-from-hashicorp-vault}

- GitLab 15.9에서 발표
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/353080)를 참조하세요.

기본 HashiCorp Vault 통합을 사용할 때 Vault에서 시크릿이 반환되지 않으면 CI/CD 작업이 실패합니다. 구성이 항상 시크릿을 반환하거나 GitLab 16.0 이전에 이 변경을 처리하도록 파이프라인을 업데이트해야 합니다.

### 다중 모듈 Android 프로젝트에서 MobSF 기반 SAST 분석기 동작 변경 {#changing-mobsf-based-sast-analyzer-behavior-in-multi-module-android-projects}

- GitLab 16.0에서 발표
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/408396)를 참조하세요.

**업데이트**: 이전에 MobSF 기반 GitLab SAST 분석기가 다중 모듈 Android 프로젝트를 스캔하는 방법에 대한 변경을 발표했습니다. 해당 변경을 취소했으며 아무 조치도 필요하지 않습니다.

단일 모듈을 스캔할 것을 변경하는 대신 [다중 모듈 지원을 개선](https://gitlab.com/gitlab-org/security-products/analyzers/mobsf/-/merge_requests/73)했습니다.

### `/approvals` API 엔드포인트를 사용한 머지 리퀘스트 승인 변경 {#changing-merge-request-approvals-with-the-approvals-api-endpoint}

- GitLab 14.0에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/353097)를 참조하세요.

머지 리퀘스트에 필요한 승인을 변경하려면 더 이상 GitLab 14.0에서 지원 중단된 `/approvals` API 엔드포인트를 사용하면 안 됩니다.

대신 [`/approval_rules` 엔드포인트](https://docs.gitlab.com/api/merge_request_approvals/#merge-request-level-mr-approvals)를 사용하여 머지 리퀘스트의 승인 규칙을 [생성](https://docs.gitlab.com/api/merge_request_approvals/#create-merge-request-level-rule) 또는 [업데이트](https://docs.gitlab.com/api/merge_request_approvals/#update-merge-request-level-rule)하세요.

### Conan 프로젝트 수준 검색 엔드포인트는 프로젝트별 결과를 반환합니다 {#conan-project-level-search-endpoint-returns-project-specific-results}

- GitLab 15.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/384455)를 참조하세요.

GitLab Conan 리포지토리를 [프로젝트 수준](https://docs.gitlab.com/user/packages/conan_repository/#add-a-remote-for-your-project) 또는 [인스턴스 수준](https://docs.gitlab.com/user/packages/conan_repository/#add-a-remote-for-your-instance) 엔드포인트와 함께 사용할 수 있습니다. 각 수준은 Conan 검색 명령을 지원합니다. 그러나 프로젝트 수준의 검색 엔드포인트는 대상 프로젝트 외부의 패키지도 반환하고 있습니다.

이 의도하지 않은 기능은 GitLab 15.8에서 지원 중단되었으며 GitLab 16.0에서 제거될 예정입니다. 프로젝트 수준의 검색 엔드포인트는 대상 프로젝트의 패키지만 반환합니다.

### GitLab Runner Helm Chart의 구성 필드 {#configuration-fields-in-gitlab-runner-helm-chart}

- GitLab 15.6에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/379064)를 참조하세요.

GitLab 13.6부터 사용자는 [GitLab Runner Helm Chart에서 모든 러너 구성을 지정](https://docs.gitlab.com/runner/install/kubernetes/)할 수 있습니다. 이 기능을 구현할 때 GitLab Helm Chart 구성에서 GitLab Runner에만 해당하는 값을 지원 중단했습니다. 지원 중단된 값은 GitLab 16.0에서 제거될 예정입니다.

### 환경 변수를 사용한 Redis 구성 파일 경로 구성이 더 이상 사용되지 않습니다 {#configuring-redis-config-file-paths-using-environment-variables-is-deprecated}

- GitLab 15.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/388255)를 참조하세요.

`GITLAB_REDIS_CACHE_CONFIG_FILE` 또는 `GITLAB_REDIS_QUEUES_CONFIG_FILE`와 같은 환경 변수를 사용하여 더 이상 Redis 구성 파일 위치를 지정할 수 없습니다. 대신 기본 구성 파일 위치(예: `config/redis.cache.yml` 또는 `config/redis.queues.yml`)를 사용하세요.

### 컨테이너 레지스트리 풀스루 캐시 {#container-registry-pull-through-cache}

- GitLab 15.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/container-registry/-/issues/842)를 참조하세요.

컨테이너 레지스트리 [풀스루 캐시](https://docs.docker.com/docker-hub/image-library/mirror/)는 GitLab 15.8에서 지원 중단되었으며 GitLab 16.0에서 제거될 예정입니다. 풀스루 캐시는 업스트림 [Docker 배포 프로젝트](https://github.com/distribution/distribution)의 일부입니다. 그러나 Docker Hub에서 컨테이너 이미지를 프록시 및 캐시할 수 있도록 하는 GitLab 종속성 프록시를 선호하여 풀스루 캐시를 제거하고 있습니다. 풀스루 캐시를 제거하면 기능을 포기하지 않고도 업스트림 클라이언트 코드를 제거할 수 있습니다.

### Docker를 참조하는 컨테이너 검사 변수 {#container-scanning-variables-that-reference-docker}

- GitLab 15.4에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/371840)를 참조하세요.

변수 이름에 `DOCKER_`이 접두사로 붙은 모든 컨테이너 검사 변수는 더 이상 사용되지 않습니다. 여기에는 `DOCKER_IMAGE`, `DOCKER_PASSWORD`, `DOCKER_USER` 및 `DOCKERFILE_PATH` 변수가 포함됩니다. 이러한 변수에 대한 지원은 GitLab 16.0 릴리스에서 제거될 예정입니다. 지원되는 이름 대신 [새 변수 이름](https://docs.gitlab.com/user/application_security/container_scanning/#available-cicd-variables) `CS_IMAGE`, `CS_REGISTRY_PASSWORD`, `CS_REGISTRY_USER` 및 `CS_DOCKERFILE_PATH`을 사용하세요.

### GitLab for Jira Cloud 앱의 쿠키 인증 {#cookie-authorization-in-the-gitlab-for-jira-cloud-app}

- GitLab 15.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/387299)를 참조하세요.

GitLab for Jira Cloud 앱의 쿠키 인증은 이제 OAuth 인증을 사용하도록 지원 중단되었습니다. GitLab Self-Managed에서는 GitLab for Jira Cloud 앱을 계속 사용하려면 [OAuth 인증을 설정](https://docs.gitlab.com/integration/jira/connect-app/#set-up-oauth-authentication-for-self-managed-instances)해야 합니다. OAuth 없이는 연결된 네임스페이스를 관리할 수 없습니다.

### DAST 템플릿을 사용하는 DAST API 스캔은 지원 중단됨 {#dast-api-scans-using-dast-template-is-deprecated}

- GitLab 15.7에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/384198)를 참조하세요.

새로운 DAST API 분석기로 이동하고 DAST API 스캔용 `DAST-API.gitlab-ci.yml` 템플릿을 사용하면 DAST 분석기로 API를 스캔할 수 있는 기능이 제거됩니다. API 스캔에 `DAST.gitlab-ci.yml` 또는 `DAST-latest.gitlab-ci.yml` 템플릿을 사용하는 것은 GitLab 15.7부터 지원 중단되었으며 GitLab 16.0에서는 더 이상 작동하지 않습니다. `DAST-API.gitlab-ci.yml` 템플릿을 사용하고 구성 세부 정보는 [DAST API 분석기](https://docs.gitlab.com/user/application_security/dast_api/#configure-dast-api-with-an-openapi-specification) 설명서를 참조하세요.

### DAST API 변수 {#dast-api-variables}

- GitLab 15.7에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/383467)를 참조하세요.

GitLab 15.6에서 새로운 DAST API 분석기로 전환하면서 두 개의 레거시 DAST API 변수가 지원 중단됩니다. `DAST_API_HOST_OVERRIDE` 및 `DAST_API_SPECIFICATION` 변수는 더 이상 DAST API 스캔에 사용되지 않습니다.

`DAST_API_HOST_OVERRIDE`는 OpenAPI 사양의 호스트를 자동으로 재정의하기 위해 `DAST_API_TARGET_URL`를 사용하는 것을 지원 중단했습니다.

`DAST_API_SPECIFICATION`는 `DAST_API_OPENAPI`를 지원 중단했습니다. 테스트를 안내하기 위해 OpenAPI 사양을 계속 사용하려면 사용자는 `DAST_API_SPECIFICATION` 변수를 `DAST_API_OPENAPI` 변수로 바꿔야 합니다. 값은 동일하게 유지될 수 있지만 변수 이름을 바꿔야 합니다.

이 두 변수는 GitLab 16.0에서 제거됩니다.

### DAST 보고서 변수 지원 중단 {#dast-report-variables-deprecation}

- GitLab 15.7에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/384340)를 참조하세요.

GitLab 15.7에서 새로운 브라우저 기반 DAST 분석기 GA를 통해 향후 어느 시점에서 기본 DAST 분석기로 만드는 작업을 하고 있습니다. 이를 준비하기 위해 다음 레거시 DAST 변수가 지원 중단되고 GitLab 16.0에서 제거될 예정입니다: `DAST_HTML_REPORT`, `DAST_XML_REPORT`, 및 `DAST_MARKDOWN_REPORT`. 이 보고서는 레거시 DAST 분석기를 기반으로 했으며 새로운 브라우저 기반 분석기에 구현할 계획이 없습니다. GitLab 16.0부터 이 보고서 아티팩트는 더 이상 생성되지 않습니다.

이 세 변수는 GitLab 16.0에서 제거됩니다.

### Java 13, 14, 15, 16에 대한 종속성 검사 지원 {#dependency-scanning-support-for-java-13-14-15-and-16}

- GitLab 15.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/387560)를 참조하세요.

GitLab은 Java 버전 13, 14, 15, 16에 대한 종속성 검사 지원을 지원 중단했으며 다음 GitLab 16.0 릴리스에서 해당 지원을 제거할 계획입니다. 이는 [Oracle 지원 정책](https://www.oracle.com/java/technologies/java-se-support-roadmap.html)과 일치합니다. Oracle Premier 및 Extended Support가 이러한 버전에 대해 종료되었습니다. 또한 GitLab이 향후 종속성 검사 Java 지원을 LTS 버전에 집중할 수 있습니다.

### `updated_at` 및 `updated_at`를 함께 사용하지 않으면 배포 API가 오류를 반환합니다 {#deployment-api-returns-error-when-updated_at-and-updated_at-are-not-used-together}

- GitLab 15.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/328500)를 참조하세요.

배포 API는 이제 `updated_at` 필터링과 `updated_at` 정렬을 함께 사용하지 않으면 오류를 반환합니다. 일부 사용자는 `updated_at` 정렬을 사용하지 않고 "최신" 배포를 가져오기 위해 `updated_at`로 필터링하고 있었는데, 이는 잘못된 결과를 생성할 수 있습니다. 대신 이들을 함께 사용하거나 `finished_at`로 필터링하고 `finished_at`로 정렬하도록 마이그레이션해야 합니다. 이렇게 하면 일관되게 "최신 배포"를 얻을 수 있습니다.

### 레거시 Gitaly 구성 방법 지원 중단 {#deprecate-legacy-gitaly-configuration-methods}

- GitLab 14.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/352609)를 참조하세요.

환경 변수 `GIT_CONFIG_SYSTEM` 및 `GIT_CONFIG_GLOBAL`를 사용하여 Gitaly를 구성하는 것은 [지원 중단되었습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/352609). 이 변수는 표준 [`config.toml` Gitaly 구성](https://docs.gitlab.com/administration/gitaly/)으로 바뀝니다.

Gitaly를 구성하기 위해 `GIT_CONFIG_SYSTEM` 및 `GIT_CONFIG_GLOBAL`를 사용하는 GitLab 인스턴스는 `config.toml`를 사용하여 구성하도록 전환해야 합니다.

### 지원 중단된 Consul http 메트릭 {#deprecated-consul-http-metrics}

- GitLab 15.10에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/7278)를 참조하세요.

Linux 패키지에서 제공하는 Consul은 GitLab 16.0부터 더 이상 오래된 지원 중단된 Consul 메트릭을 제공하지 않습니다.

GitLab 14.0에서는 [Consul이 1.9.6으로 업데이트](https://gitlab.com/gitlab-org/omnibus-gitlab/-/merge_requests/5344)되었으며, 이로 인해 일부 원격 측정 메트릭이 `consul.http` 경로에 있던 것이 지원 중단되었습니다. GitLab 16.0에서는 `consul.http` 경로가 제거됩니다.

Consul 메트릭을 사용하는 모니터링이 있으면 `consul.http` 대신 `consul.api.http`를 사용하도록 업데이트하세요. 자세한 내용은 [Consul 1.9.0의 지원 중단 노트](https://github.com/hashicorp/consul/releases/tag/v1.9.0)를 참조하세요.

### GitLab.com에서 `CI_PRE_CLONE_SCRIPT` 변수의 지원 중단 및 계획된 제거 {#deprecation-and-planned-removal-for-ci_pre_clone_script-variable-on-gitlabcom}

- GitLab 15.9에서 발표
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/391896)를 참조하세요.

GitLab.com 러너에서 지원하는 [`CI_PRE_CLONE_SCRIPT` 변수](https://docs.gitlab.com/ci/runners/saas/linux_saas_runner/#pre-clone-script)는 GitLab 15.9부터 지원 중단되었으며 16.0에서 제거됩니다. `CI_PRE_CLONE_SCRIPT` 변수를 사용하면 러너가 Git init 및 get fetch를 실행하기 전에 CI/CD 작업에서 명령을 실행할 수 있습니다. 이 기능이 어떻게 작동하는지에 대한 자세한 내용은 [사전 복제 스크립트](https://docs.gitlab.com/ci/runners/saas/linux_saas_runner/#pre-clone-script)를 참조하세요. 또는 [`pre_get_sources_script`](https://docs.gitlab.com/ci/yaml/#hookspre_get_sources_script)를 사용할 수 있습니다.

### 그룹으로 프로젝트를 가져올 수 있는 개발자 역할 {#developer-role-providing-the-ability-to-import-projects-to-a-group}

- GitLab 15.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/387891)를 참조하세요.

그룹의 개발자 역할을 가진 사용자가 해당 그룹으로 프로젝트를 가져올 수 있는 기능은 GitLab 15.8에서 지원 중단되었으며 GitLab 16.0에서 제거됩니다. GitLab 16.0부터는 그룹의 유지 관리자 또는 소유자 역할을 가진 사용자만 해당 그룹으로 프로젝트를 가져올 수 있습니다.

### PHP 및 Python에 대해 보고된 개발 종속성 {#development-dependencies-reported-for-php-and-python}

- GitLab 15.9에서 발표
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/375505)를 참조하세요.

GitLab 16.0에서 GitLab 종속성 검사 분석기는 Python/pipenv 및 PHP/composer 프로젝트 모두에 대한 개발 종속성 보고를 시작합니다. 이러한 개발 종속성이 보고되는 것을 원하지 않는 사용자는 CI/CD 파일에서 `DS_INCLUDE_DEV_DEPENDENCIES: false`을 설정해야 합니다.

### Markdown에 Grafana 패널 포함 지원 중단 {#embedding-grafana-panels-in-markdown-is-deprecated}

- GitLab 15.9에서 발표
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/389477)를 참조하세요.

GitLab Flavored Markdown에 Grafana 패널을 추가할 수 있는 기능은 15.9에서 지원 중단되고 16.0에서 제거됩니다. 이 기능을 [GitLab 관찰성 UI](https://gitlab.com/gitlab-org/opstrace/opstrace-ui)를 사용하여 [차트를 포함](https://gitlab.com/groups/gitlab-org/opstrace/-/epics/33)할 수 있는 기능으로 바꿀 계획입니다.

### CI/CD 매개변수 문자 길이의 강제 검증 {#enforced-validation-of-cicd-parameter-character-lengths}

- GitLab 15.9에서 발표
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/372770)를 참조하세요.

CI/CD [작업 이름](https://docs.gitlab.com/ci/jobs/#job-name)에는 엄격한 255자 제한이 있지만 다른 CI/CD 매개변수는 아직 이 제한 이상으로 유지되도록 하는 검증이 없습니다.

GitLab 16.0에서는 다음을 255자로 엄격히 제한하는 검증이 추가됩니다:

- `stage` 키워드입니다.
- 파이프라인의 Git 브랜치 또는 태그 이름인 `ref`입니다.
- 외부 CI/CD 통합에서 사용되는 `description` 및 `target_url` 매개변수입니다.

GitLab Self-Managed 사용자는 255자를 초과하지 않는 매개변수를 사용하도록 파이프라인을 업데이트해야 합니다. GitLab.com 사용자는 이 데이터베이스에서 이미 제한되어 있으므로 변경할 필요가 없습니다.

### 환경 검색 쿼리에 최소 3자 필요 {#environment-search-query-requires-at-least-three-characters}

- GitLab 15.10에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/382532)를 참조하세요.

GitLab 16.0부터 API를 사용하여 환경을 검색할 때 최소 3자를 사용해야 합니다. 이 변경은 검색 작업의 확장성을 보장하는 데 도움이 됩니다.

### GraphQL ReleaseAssetLink 유형의 외부 필드 {#external-field-in-graphql-releaseassetlink-type}

- GitLab 15.9에서 발표
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))

[GraphQL API](https://docs.gitlab.com/api/graphql/)에서 [`ReleaseAssetLink` 유형](https://docs.gitlab.com/api/graphql/reference/objects/#releaseassetlink)의 `external` 필드는 [릴리스 링크](https://docs.gitlab.com/user/project/releases/release_fields/#links)가 GitLab 인스턴스의 내부인지 외부인지 나타내는 데 사용되었습니다. GitLab 15.9부터 모든 릴리스 링크를 외부로 취급하므로 이 필드는 GitLab 15.9에서 지원 중단되고 GitLab 16.0에서 제거됩니다. 워크플로 중단을 방지하려면 `external` 필드 사용을 중단하세요. 이 필드는 제거되고 교체되지 않기 때문입니다.

### 릴리스 및 릴리스 링크API의 외부 필드 {#external-field-in-releases-and-release-links-apis}

- GitLab 15.9에서 발표
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))

[릴리스 API](https://docs.gitlab.com/api/releases/) 및 [릴리스 링크 API](https://docs.gitlab.com/api/releases/links/)에서 `external` 필드는 [릴리스 링크](https://docs.gitlab.com/user/project/releases/release_fields/#links)가 GitLab 인스턴스의 내부인지 외부인지 나타내는 데 사용되었습니다. GitLab 15.9부터 모든 릴리스 링크를 외부로 취급하므로 이 필드는 GitLab 15.9에서 지원 중단되고 GitLab 16.0에서 제거됩니다. 워크플로 중단을 방지하려면 `external` 필드 사용을 중단하세요. 이 필드는 제거되고 교체되지 않기 때문입니다.

### Geo: 프로젝트 리포지토리 다시 다운로드가 지원 중단됨 {#geo-project-repository-redownload-is-deprecated}

- GitLab 15.11에서 발표됨
- GitLab 16.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/388868)를 참조하세요.

보조 Geo 사이트에서 프로젝트 리포지토리를 "다시 다운로드"하는 버튼이 지원 중단됩니다. 다시 다운로드 로직은 발생할 때 해결하기 어려운 데이터 일관성 문제가 있습니다. 이 버튼은 GitLab 16.0에서 제거됩니다.

### GitLab 관리자는 보호된 브랜치 또는 태그를 수정할 권한이 있어야 함 {#gitlab-administrators-must-have-permission-to-modify-protected-branches-or-tags}

- GitLab 16.0에서 발표
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/12776)를 참조하세요.

GitLab 관리자는 명시적으로 권한이 부여되지 않으면 보호된 브랜치 또는 태그에서 작업을 수행할 수 없습니다. 이러한 작업에는 [보호된 브랜치](https://docs.gitlab.com/user/project/repository/branches/protected/)로 푸시 및 병합, 브랜치 보호 해제, [보호된 태그](https://docs.gitlab.com/user/project/protected_tags/) 생성이 포함됩니다.

### GitLab 자체 모니터링 프로젝트 {#gitlab-self-monitoring-project}

- GitLab 14.9에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/348909)를 참조하세요.

GitLab 자체 모니터링은 인스턴스 관리자에게 인스턴스 상태를 모니터링할 수 있는 도구를 제공합니다. 이 기능은 GitLab 14.9에서 지원 중단되었으며 16.0에서 제거될 예정입니다.

### GitLab.com 가져오기 {#gitlabcom-importer}

- GitLab 15.8에서 발표됨
- GitLab 16.0에서 제거

GitLab.com 가져오기는 GitLab 15.8에서 지원 중단되었으며 GitLab 16.0에서 제거될 예정입니다.

GitLab.com 가져오기는 2015년에 GitLab.com에서 UI를 통해 GitLab Self-Managed 인스턴스로 프로젝트를 가져오기 위해 도입되었습니다. 이 기능은 GitLab Self-Managed에서만 사용 가능합니다. [직접 전송으로 GitLab 그룹 및 프로젝트 마이그레이션](https://docs.gitlab.com/user/group/import/#migrate-groups-by-direct-transfer-recommended)은 GitLab.com 가져오기를 대신하며 더욱 일관된 가져오기 기능을 제공합니다.

개요는 [마이그레이션된 그룹 항목](https://docs.gitlab.com/user/group/import/#migrated-group-items) 및 [마이그레이션된 프로젝트 항목](https://docs.gitlab.com/user/group/import/#migrated-project-items)을 참조하세요.

### GraphQL API 러너 상태는 `paused`을 반환하지 않습니다 {#graphql-api-runner-status-will-not-return-paused}

- GitLab 14.5에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/344648)를 참조하세요.

GitLab Runner GraphQL API 엔드포인트는 GitLab 16.0에서 `paused` 또는 `active`을 상태로 반환하지 않습니다. REST API의 향후 v5에서 GitLab Runner용 엔드포인트도 `paused` 또는 `active`를 반환하지 않습니다.

러너의 상태는 러너 연결 상태에만 관련됩니다. 예: `online`, `offline`, 또는 `not_connected`. 상태 `paused` 또는 `active`는 더 이상 나타나지 않습니다.

러너가 `paused`인지 확인할 때 API 사용자는 부울 속성 `paused`이 `true`인지 확인하도록 권장됩니다. 러너가 `active`인지 확인할 때는 `paused`이 `false`인지 확인하세요.

### Jira Cloud를 위한 Jira DVCS 커넥터 {#jira-dvcs-connector-for-jira-cloud}

- GitLab 15.1에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/groups/gitlab-org/-/epics/7508)를 참조하세요.

Jira Cloud를 위한 [Jira DVCS 커넥터](https://docs.gitlab.com/integration/jira/dvcs/)가 지원 중단되었으며 GitLab 16.0에서 제거될 예정입니다. Jira Cloud에서 Jira DVCS 커넥터를 사용하고 있으면 [GitLab for Jira Cloud 앱](https://docs.gitlab.com/integration/jira/connect-app/)으로 마이그레이션하세요.

Jira DVCS 커넥터는 또한 Jira 8.13 이하에서도 지원 중단되었습니다. Jira DVCS 커넥터는 Jira 8.14 이상에서만 Jira Server 또는 Jira Data Center에서만 사용할 수 있습니다.

### GitLab Helm 차트의 KAS 메트릭 포트 {#kas-metrics-port-in-gitlab-helm-chart}

- GitLab 15.7에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/383039)를 참조하세요.

`gitlab.kas.metrics.port`는 [GitLab Helm 차트](https://gitlab.com/gitlab-org/charts/gitlab/-/merge_requests/2839)의 새로운 `gitlab.kas.observability.port` 구성 필드로 대신합니다. 이 포트는 메트릭 이상으로 많은 용도로 사용되므로 구성의 혼동을 피하기 위해 이 변경이 필요했습니다.

### 레거시 Gitaly 구성 방법 {#legacy-gitaly-configuration-method}

- GitLab 15.10에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/393574)를 참조하세요.

Omnibus GitLab 내의 Gitaly 구성이 업데이트되었으므로 모든 Gitaly 관련 구성 키가 표준 Gitaly 구성과 일치하는 단일 구성 구조에 있습니다. 따라서 이전 구성 구조는 지원 중단되었습니다.

단일 구성 구조는 GitLab 15.10부터 사용 가능하지만 하위 호환성이 유지됩니다. 제거되면 Gitaly를 단일 구성 구조를 사용하여 구성해야 합니다. 가능한 빨리 Gitaly의 구성을 업데이트해야 합니다.

이 변경은 Omnibus GitLab과 소스 설치 간의 일관성을 개선하고 둘 다에 대해 더 나은 설명서 및 도구를 제공할 수 있게 합니다.

[업그레이드 지침](https://docs.gitlab.com/update/#gitaly-omnibus-gitlab-configuration-structure-change)을 사용하여 가능한 빨리 새 구성 구조로 업데이트해야 합니다.

### 레거시 Praefect 구성 방법 {#legacy-praefect-configuration-method}

- GitLab 15.9에서 발표
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/390291)를 참조하세요.

이전에는 Praefect 구성 키가 구성 파일 전체에 흩어져 있었습니다. 이제 이들은 Praefect 구성과 일치하는 단일 구성 구조에 있으므로 이전 구성 방법은 지원 중단되었습니다.

단일 구성 구조는 GitLab 15.9부터 사용 가능하지만 하위 호환성이 유지됩니다. 제거되면 Praefect를 단일 구성 구조를 사용하여 구성해야 합니다. 가능한 빨리 [업그레이드 지침](https://docs.gitlab.com/update/#praefect-omnibus-gitlab-configuration-structure-change)을 사용하여 Praefect 구성을 업데이트해야 합니다.

이 변경은 Omnibus GitLab의 Praefect 구성을 Praefect의 구성 구조와 일치시킵니다. 이전에는 계층 및 구성 키가 일치하지 않았습니다. 이 변경은 Omnibus GitLab과 소스 설치 간의 일관성을 개선하고 둘 다에 대해 더 나은 설명서 및 도구를 제공할 수 있게 합니다.

### 레거시 URL이 교체되거나 제거됨 {#legacy-urls-replaced-or-removed}

- GitLab 15.9에서 발표
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/214217)를 참조하세요.

GitLab 16.0은 GitLab 애플리케이션의 레거시 URL을 제거합니다.

GitLab 9.0에서 하위 그룹이 도입되었을 때 `/-/` 구분 기호가 URL에 추가되어 그룹 경로의 끝을 나타냈습니다. 모든 GitLab URL은 이제 프로젝트, 그룹 및 인스턴스 수준 기능에 대해 이 구분 기호를 사용합니다.

`/-/` 구분 기호를 사용하지 않는 URL은 GitLab 16.0에서 제거될 계획입니다. 이러한 URL의 전체 목록과 해당 대체 URL은 [이슈 28848](https://gitlab.com/gitlab-org/gitlab/-/issues/28848#release-notes)을 참조하세요.

레거시 URL을 참조하는 모든 스크립트 또는 책갈피를 업데이트하세요. GitLab API는 이 변경의 영향을 받지 않습니다.

### 라이선스 검사 및 라이선스 규정 준수 페이지의 정책 탭 {#license-check-and-the-policies-tab-on-the-license-compliance-page}

- GitLab 15.9에서 발표
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/390417)를 참조하세요.

**라이선스 검사 기능**은 이제 지원 중단되었으며 GitLab 16.0에서 제거될 예정입니다. 또한 라이선스 규정 준수 페이지의 정책 탭 및 라이선스 검사 기능과 관련된 모든 API는 지원 중단되었으며 GitLab 16.0에서 제거될 예정입니다. 감지된 라이선스를 기반으로 승인을 계속 시행하려는 사용자는 새로운 [라이선스 승인 정책](https://docs.gitlab.com/user/compliance/license_approval_policies/)을 대신 생성하도록 권장됩니다.

### 외부 권한 부여를 사용하여 개인 액세스 토큰 및 배포 토큰의 액세스 제한 {#limit-personal-access-token-and-deploy-tokens-access-with-external-authorization}

- GitLab 15.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/387721)를 참조하세요.

외부 권한 부여가 활성화된 상태에서는 개인 액세스 토큰(PAT) 및 배포 토큰이 더 이상 컨테이너 또는 패키지 레지스트리에 액세스할 수 없어야 합니다. 이 심층 방어 보안 조치는 16.0에서 배포될 예정입니다. 이 레지스트리에 액세스하기 위해 PAT 및 배포 토큰을 사용하는 사용자의 경우 이 조치가 이 토큰의 사용을 방해합니다. 외부 권한 부여를 비활성화하여 토큰을 컨테이너 또는 패키지 레지스트리와 함께 사용합니다.

### GitLab Helm 차트의 주요 번들 Helm 차트 업데이트 {#major-bundled-helm-chart-updates-for-the-gitlab-helm-chart}

- GitLab 15.10에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/3442)를 참조하세요.

GitLab 16.0과 동시에 GitLab Helm 차트는 7.0 메이저 버전을 릴리스합니다. 다음과 같은 주요 번들 차트 업데이트가 포함됩니다:

- GitLab 16.0에서는 [PostgreSQL 12 지원이 제거되고 PostgreSQL 13이 새 최소값](#postgresql-12-deprecated)이 됩니다.
  - 프로덕션 지원 외부 데이터베이스를 사용하는 설치는 업그레이드 전에 더 최신 PostgreSQL 버전으로의 마이그레이션을 완료해야 합니다.
  - [프로덕션이 아닌 번들 PostgreSQL 12 차트](https://docs.gitlab.com/charts/installation/tools/#postgresql)를 사용하는 설치는 차트를 새 버전으로 업그레이드합니다. 자세한 내용은 [이슈 4118](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/4118)을 참조하세요
- [프로덕션이 아닌 번들 Redis 차트](https://docs.gitlab.com/charts/installation/tools/#redis)를 사용하는 설치는 차트를 더 최신 버전으로 업그레이드합니다. 자세한 내용은 [이슈 3375](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/3375)를 참조하세요
- [번들 cert-manager 차트](https://docs.gitlab.com/charts/installation/tls/#option-1-cert-manager-and-lets-encrypt)를 사용하는 설치는 차트를 더 최신 버전으로 업그레이드합니다. 자세한 내용은 [이슈 4313](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/4313)을 참조하세요

전체 GitLab Helm 차트 7.0 업그레이드 단계는 [업그레이드 문서](https://docs.gitlab.com/charts/installation/upgrade/)에서 사용할 수 있습니다.

### 관리되는 라이선스 API {#managed-licenses-api}

- GitLab 15.9에서 발표
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/390417)를 참조하세요.

관리되는 라이선스 API는 이제 지원 중단되었으며 GitLab 16.0에서 제거될 예정입니다.

### 프로젝트당 활성 파이프라인의 최대 개수 제한(`ci_active_pipelines`) {#maximum-number-of-active-pipelines-per-project-limit-ci_active_pipelines}

- GitLab 15.3에서 발표됨
- GitLab 16.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/368195)를 참조하세요.

[**프로젝트당 활성 파이프라인의 최대 개수** 제한](https://docs.gitlab.com/administration/settings/continuous_integration/#set-cicd-limits)은 기본적으로 활성화되지 않았으며 GitLab 16.0에서 제거됩니다. 이 제한은 [`ci_active_pipelines`](https://docs.gitlab.com/administration/instance_limits/#number-of-pipelines-running-concurrently)의 Rails 콘솔에서도 구성할 수 있습니다. 대신 유사한 보호를 제공하는 다른 권장 속도 제한을 사용합니다:

- [**파이프라인 속도 제한**](https://docs.gitlab.com/administration/settings/rate_limit_on_pipelines_creation/).
- [**현재 활성 파이프라인의 총 작업 개수**](https://docs.gitlab.com/administration/settings/continuous_integration/#set-cicd-limits).

### Prometheus를 통한 성능 메트릭 모니터링 {#monitor-performance-metrics-through-prometheus}

- GitLab 14.7에서 공지
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/346541)를 참조하세요.

Prometheus 인스턴스에 저장된 데이터를 표시하여 GitLab을 통해 사용자가 성능 메트릭을 볼 수 있습니다. GitLab은 또한 대시보드에 이러한 메트릭의 시각화를 표시합니다. 사용자는 이전에 구성된 외부 Prometheus 인스턴스에 연결하거나 Prometheus를 GitLab Managed App으로 설정할 수 있습니다. 하지만 Kubernetes 클러스터와의 인증서 기반 통합이 GitLab에서 지원 중단되었으므로 Prometheus에 의존하는 GitLab의 메트릭 기능도 지원 중단되었습니다. 여기에는 대시보드의 메트릭 시각화가 포함됩니다. GitLab은 [Opstrace](https://about.gitlab.com/press/releases/2021-12-14-gitlab-acquires-opstrace-to-expand-its-devops-platform-with-open-source-observability-solution/)를 기반으로 하는 단일 사용자 경험을 개발하기 위해 노력 중입니다. Opstrace 통합 작업을 따르기 위한 [이슈가 존재](https://gitlab.com/groups/gitlab-org/-/epics/6976)합니다.

### 만료되지 않는 액세스 토큰 {#non-expiring-access-tokens}

- GitLab 15.4에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/369122)를 참조하세요.

기존 프로젝트 액세스 토큰에 만료 날짜가 자동으로 적용되는지는 보유 중인 GitLab 제공 서비스와 GitLab 16.0 이상으로 업그레이드한 시기에 따라 다릅니다:

- GitLab.com에서는 16.0 마일스톤 중에 만료 날짜가 없는 기존 프로젝트 액세스 토큰에 현재 날짜보다 365일 뒤의 만료 날짜가 자동으로 부여되었습니다.
- GitLab Self-Managed에서 GitLab 15.11 이전 버전에서 GitLab 16.0 이상으로 업그레이드한 경우:
  - 2024년 7월 23일 이전에 만료 날짜가 없는 기존 프로젝트 액세스 토큰에 현재 날짜보다 365일 뒤의 만료 날짜가 자동으로 부여되었습니다. 이는 호환성이 깨지는 변경입니다.
  - 2024년 7월 24일 이후에는 만료 날짜가 없는 기존 프로젝트 액세스 토큰에 만료 날짜가 설정되지 않았습니다.

GitLab Self-Managed에서 다음 GitLab 버전 중 하나를 새로 설치하는 경우 기존 프로젝트 액세스 토큰에 만료 날짜가 자동으로 적용되지 않습니다:

- 16.0.9
- 16.1.7
- 16.2.10
- 16.3.8
- 16.4.6
- 16.5.9
- 16.6.9
- 16.7.9
- 16.8.9
- 16.9.10
- 16.10.9
- 16.11.7
- 17.0.5
- 17.1.3
- 17.2.1

만료 날짜가 없는 액세스 토큰은 무기한 유효하므로 액세스 토큰이 유출될 경우 보안 위험이 있습니다. 만료 날짜가 있는 액세스 토큰이 더 나으므로 GitLab 15.3부터 [기본 만료 날짜를 채웁니다](https://gitlab.com/gitlab-org/gitlab/-/issues/348660).

GitLab 16.0에서는 만료 날짜가 없는 [개인](https://docs.gitlab.com/user/profile/personal_access_tokens/), [프로젝트](https://docs.gitlab.com/user/project/settings/project_access_tokens/), 또는 [그룹](https://docs.gitlab.com/user/group/settings/group_access_tokens/) 액세스 토큰에 자동으로 1년의 만료 날짜가 설정됩니다.

기본값이 적용되기 전에 회사의 보안 정책에 따라 액세스 토큰에 만료 날짜를 지정하도록 권장합니다:

- GitLab.com의 16.0 마일스톤 중에.
- GitLab Self-Managed에서 16.0으로 업그레이드할 때.

### 표준이 아닌 기본 Redis 포트가 지원 중단됨 {#non-standard-default-redis-ports-are-deprecated}

- GitLab 15.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/388269)를 참조하세요.

GitLab이 Redis 구성 파일 없이 시작되면 GitLab은 `localhost:6380`, `localhost:6381` 및 `localhost:6382`의 세 Redis 서버에 연결할 수 있다고 가정합니다. GitLab이 `localhost:6379`의 하나의 Redis 서버가 있다고 가정하도록 이 동작을 변경하고 있습니다.

세 서버를 유지하려는 관리자는 `config/redis.cache.yml`, `config/redis.queues.yml` 및 `config/redis.shared_state.yml` 파일을 편집하여 Redis URL을 구성해야 합니다.

### 삭제 보호 설정에서 프로젝트를 즉시 삭제할 수 있는 옵션이 지원 중단됨 {#option-to-delete-projects-immediately-is-deprecated-from-deletion-protection-settings}

- GitLab 15.9에서 발표
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/389557)를 참조하세요.

**운영자** 영역의 그룹 및 프로젝트 삭제 보호 설정에는 그룹 및 프로젝트를 즉시 삭제할 수 있는 옵션이 있었습니다. 16.0부터는 이 옵션을 더 이상 사용할 수 없으며 지연된 그룹 및 프로젝트 삭제가 기본 동작이 됩니다.

이 옵션은 더 이상 그룹 설정으로 표시되지 않습니다. GitLab Self-Managed 사용자는 여전히 삭제 지연 기간을 정의할 수 있는 옵션이 있으며 GitLab.com 사용자는 조정할 수 없는 기본 보존 기간이 7일입니다. 사용자는 프로젝트 설정에서 프로젝트를 즉시 삭제할 수 있으며 그룹 설정에서 그룹을 삭제할 수 있습니다.

기본적으로 그룹 및 프로젝트를 즉시 삭제할 수 있는 옵션이 사용자가 실수로 이 작업을 수행하고 영구적으로 그룹 및 프로젝트를 잃는 것을 방지하기 위해 지원 중단되었습니다.

### PostgreSQL 12 지원 중단됨 {#postgresql-12-deprecated}

- GitLab 15.0에서 공지
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/349185)를 참조하세요.

PostgreSQL 12에 대한 지원은 GitLab 16.0에서 제거될 예정입니다. GitLab 16.0에서 PostgreSQL 13이 최소 필수 PostgreSQL 버전이 됩니다.

PostgreSQL 12는 전체 GitLab 15 릴리스 주기 동안 지원됩니다. PostgreSQL 13도 GitLab 16.0 전에 업그레이드하려는 인스턴스에 대해 지원됩니다.

GitLab 15.2에서 Geo에 PostgreSQL 13에 대한 지원이 추가되었습니다.

### 프로젝트 API 필드 `operations_access_level`가 지원 중단됨 {#projects-api-field-operations_access_level-is-deprecated}

- GitLab 15.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/385798)를 참조하세요.

프로젝트 API에서 `operations_access_level` 필드를 지원 중단하고 있습니다. 이 필드는 특정 기능을 제어하는 필드로 대체되었습니다: `releases_access_level`, `environments_access_level`, `feature_flags_access_level`, `infrastructure_access_level`, 및 `monitor_access_level`.

### 베어 리포지토리 가져오기용 Rake 작업 {#rake-task-for-importing-bare-repositories}

- GitLab 15.8에서 발표됨
- GitLab 16.0에서 제거

베어 리포지토리를 가져오기 위한 Rake 작업(`gitlab:import:repos`)은 GitLab 15.8에서 지원 중단되었으며 GitLab 16.0에서 제거될 예정입니다.

이 Rake 작업은 리포지토리의 디렉터리 트리를 GitLab 인스턴스로 가져옵니다. Rake 작업이 작동하려면 특정 디렉터리 구조 또는 특정 사용자 정의 Git 설정(`gitlab.fullpath`)에 의존하기 때문에 이러한 리포지토리는 이전에 GitLab에서 관리했어야 합니다.

이 Rake 작업을 사용한 리포지토리 가져오기에는 제한 사항이 있습니다. Rake 작업:

- 프로젝트 및 프로젝트 wiki 리포지토리만 알고 있으며 디자인, 그룹 wiki 또는 스니펫용 리포지토리는 지원하지 않습니다.
- 지원되지 않는 경우에도 비해시된 저장소 프로젝트를 가져올 수 있습니다.
- Git 구성 `gitlab.fullpath`이 설정된 경우에 의존합니다. [에픽 8953](https://gitlab.com/groups/gitlab-org/-/epics/8953)은 이 설정 지원 제거를 제안합니다.

`gitlab:import:repos` Rake 작업을 사용하는 대안:

- [내보내기 파일](https://docs.gitlab.com/user/project/settings/import_export/) 또는 [직접 전송](https://docs.gitlab.com/user/group/import/#migrate-groups-by-direct-transfer-recommended)을 사용하여 프로젝트를 마이그레이션하면 리포지토리도 마이그레이션됩니다.
- [URL별 리포지토리](https://docs.gitlab.com/user/project/import/repo_by_url/) 가져오기.
- [GitLab이 아닌 소스에서 리포지토리](https://docs.gitlab.com/user/import/) 가져오기.

### Redis 5 지원 중단됨 {#redis-5-deprecated}

- GitLab 15.3에서 발표됨
- GitLab 15.6에서 지원 종료
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/331468)를 참조하세요.

GitLab 13.9에서 Omnibus GitLab 패키지 및 GitLab Helm 차트 4.9의 Redis 버전이 [Redis 6으로 업데이트](https://about.gitlab.com/releases/2021/02/22/gitlab-13-9-released/#omnibus-improvements)되었습니다. Redis 5는 2022년 4월에 지원 종료에 도달했으며 GitLab 15.6부터는 더 이상 지원되지 않습니다. 자신의 Redis 5.0 인스턴스를 사용하고 있으면 GitLab 16.0 이상으로 업그레이드하기 전에 Redis 6.0 이상으로 업그레이드해야 합니다.

### `job_age` 매개변수를 `POST /jobs/request` 러너 엔드포인트에서 제거 {#remove-job_age-parameter-from-post-jobsrequest-runner-endpoint}

- GitLab 15.2에서 공지
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/334253)를 참조하세요.

GitLab Runner와의 통신에 사용되는 `POST /jobs/request` API 엔드포인트에서 반환된 `job_age` 매개변수는 GitLab 또는 Runner 기능에서 사용되지 않았습니다. 이 매개변수는 GitLab 16.0에서 제거됩니다.

이 엔드포인트에서 반환되는 이 매개변수를 기반으로 하는 자신의 러너를 개발한 사람에게는 이것이 기존 코드와 호환되지 않는 변경일 수 있습니다. 공식 출시 버전의 GitLab Runner를 사용하는 사람(GitLab.com의 공개 공유 러너 포함)에게는 기존 코드와 호환되지 않는 변경이 아닙니다.

### GitLab 16.0에서 SAST 분석기 커버리지 변경 {#sast-analyzer-coverage-changing-in-gitlab-160}

- GitLab 15.9에서 발표
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/390416)를 참조하세요.

GitLab SAST는 다양한 [분석기](https://docs.gitlab.com/user/application_security/sast/analyzers/)를 사용하여 취약성에 대한 코드를 스캔합니다.

기본적으로 GitLab SAST에서 사용되는 지원되는 분석기의 수를 줄이고 있습니다. 이는 다양한 프로그래밍 언어에서 더 빠르고 일관된 사용자 경험을 제공하려는 장기 전략의 일부입니다.

GitLab 16.0부터 GitLab SAST CI/CD 템플릿은 더 이상 [Security Code Scan](https://gitlab.com/gitlab-org/security-products/analyzers/security-code-scan) 기반 분석기를 .NET에 사용하지 않으며 지원 종료 상태로 진입합니다. 이 분석기를 [SAST CI/CD 템플릿](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/SAST.gitlab-ci.yml)에서 제거하고 [Semgrep 기반 분석기](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep)의 C#에 대한 GitLab 지원 감지 규칙으로 바꿀 것입니다.

즉시 이 분석기는 보안 업데이트만 받습니다. 다른 일반적인 개선 또는 업데이트는 보장되지 않습니다. 이 분석기가 GitLab 16.0에서 지원 종료에 도달한 후에는 추가 업데이트가 제공되지 않습니다. 하지만 이 분석기에 대해 이전에 게시된 컨테이너 이미지를 삭제하지 않거나 사용자 지정 CI/CD 파이프라인 작업을 사용하여 실행할 수 있는 기능을 제거하지 않습니다.

지원 중단된 분석기에서 취약성 발견을 이미 무시했으면 교체가 이전 무시를 존중하려고 시도합니다. 시스템 동작은 다음에 따라 달라집니다:

- 이전에 Semgrep 기반 분석기를 실행에서 제외했는지 여부입니다.
- 프로젝트의 취약성 보고서에 표시된 취약성을 먼저 발견한 분석기입니다.

[취약성 변환 문서](https://docs.gitlab.com/user/application_security/sast/analyzers/#vulnerability-translation)를 참조하여 자세한 내용을 알아보세요.

영향을 받는 분석기에 사용자 지정을 적용했거나 현재 파이프라인에서 Semgrep 기반 분석기를 비활성화하면 [이 변경의 지원 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/390416#breaking-change)에서 자세히 설명한 대로 조치를 취해야 합니다.

**업데이트**: 이 변경의 범위를 축소했습니다. GitLab 16.0에서 더 이상 다음 변경을 수행하지 않을 것입니다:

1. [PHPCS Security Audit](https://gitlab.com/gitlab-org/security-products/analyzers/phpcs-security-audit)를 기반으로 하는 분석기에 대한 지원을 제거하고 [Semgrep 기반 분석기](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep)의 GitLab 관리형 감지 규칙으로 바꿉니다.
1. [SpotBugs 기반 분석기](https://gitlab.com/gitlab-org/security-products/analyzers/spotbugs)의 범위에서 Scala를 제거하고 [Semgrep 기반 분석기](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep)의 GitLab 관리형 감지 규칙으로 바꿉니다.

PHPCS Security Audit 기반 분석기를 교체하는 작업은 [이슈 364060](https://gitlab.com/gitlab-org/gitlab/-/issues/364060)에서 추적되고 Scala 스캔을 Semgrep 기반 분석기로 마이그레이션하는 작업은 [이슈 362958](https://gitlab.com/gitlab-org/gitlab/-/issues/362958)에서 추적됩니다.

### 보안 분석기 주요 버전 업데이트 {#secure-analyzers-major-version-update-1}

- GitLab 15.9에서 발표
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/390912)를 참조하세요.

Secure 스테이지는 GitLab 16.0 릴리스와 함께 분석기의 주요 버전을 함께 범프할 것입니다. 이 범프는 분석기에 대한 명확한 경계를 활성화할 것입니다:

- 2023년 5월 22일 이전에 릴리스된 것
- 2023년 5월 22일 이후에 릴리스된 것

기본 포함 템플릿을 사용하지 않거나 분석기 버전을 고정한 경우 CI/CD 작업 정의를 업데이트하여 고정된 버전을 제거하거나 최신 주요 버전을 업데이트해야 합니다. GitLab 13.0-15.10 사용자는 GitLab 16.0이 릴리스될 때까지 일반적인 분석기 업데이트를 계속 경험할 것입니다. 그 이후로 모든 새로 수정된 버그 및 릴리스된 기능은 분석기의 새 주요 버전에서만 릴리스됩니다. 당사의 [유지 관리 정책](https://docs.gitlab.com/policy/maintenance/)에 따라 지원 중단된 버전에 버그 및 기능을 백포트하지 않습니다. 필요에 따라 최신 3개의 부 릴리스 내에서 보안 패치가 백포트됩니다. 구체적으로 16.0 GitLab 릴리스 이후로 더 이상 업데이트되지 않는 다음이 지원 중단됩니다:

- API 퍼징: 버전 2
- 컨테이너 스캔: 버전 5
- 커버리지 가이드 퍼징 테스트: 버전 3
- 종속성 검사: 버전 3
- 동적 애플리케이션 보안 테스트(DAST): 버전 3
- DAST API: 버전 2
- IaC 스캔: 버전 3
- 라이선스 스캔: 버전 4
- 시크릿 검색: 버전 4
- 정적 애플리케이션 보안 테스트(SAST): 버전 3 [모든 분석기](https://docs.gitlab.com/user/application_security/sast/#supported-languages-and-frameworks)
  - `brakeman`: 버전 3
  - `flawfinder`: 버전 3
  - `kubesec`: 버전 3
  - `mobsf`: 버전 3
  - `nodejs-scan`: 버전 3
  - `phpcs-security-audit`: 버전 3
  - `pmd-apex`: 버전 3
  - `security-code-scan`: 버전 3
  - `semgrep`: 버전 3
  - `sobelow`: 버전 3
  - `spotbugs`: 버전 3

### 안전한 스캔 CI/CD 템플릿은 새로운 작업 `rules`을 사용합니다 {#secure-scanning-cicd-templates-will-use-new-job-rules}

- GitLab 15.9에서 발표
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/391822)를 참조하세요.

보안 스캔을 위한 GitLab 관리형 CI/CD 템플릿은 GitLab 16.0 릴리스에서 업데이트됩니다. 업데이트에는 CI/CD 템플릿의 최신 버전에서 이미 릴리스된 개선 사항이 포함됩니다. 사용자 지정 CI/CD 파이프라인 구성을 방해할 수 있으므로 최신 템플릿 버전에서 이 변경을 릴리스했습니다.

모든 업데이트된 템플릿에서 `SAST_DISABLED` 및 `DEPENDENCY_SCANNING_DISABLED`와 같은 변수의 정의를 업데이트하여 값이 `"true"`일 때만 스캔을 비활성화합니다. 이전에 값이 `"false"`인 경우에도 스캔이 비활성화될 것입니다.

다음 템플릿이 업데이트됩니다:

- API 퍼징: [`API-Fuzzing.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/API-Fuzzing.gitlab-ci.yml)
- 컨테이너 스캔: [`Container-Scanning.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/Container-Scanning.gitlab-ci.yml)
- 커버리지 가이드 퍼징: [`Coverage-Fuzzing.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/Coverage-Fuzzing.gitlab-ci.yml)
- DAST: [`DAST.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/DAST.gitlab-ci.yml)
- DAST API: [`DAST-API.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/DAST-API.gitlab-ci.yml)
- 종속성 검사: [`Dependency-Scanning.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/Dependency-Scanning.gitlab-ci.yml)
- IaC 스캔: [`SAST-IaC.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/SAST-IaC.gitlab-ci.yml)
- SAST: [`SAST.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/SAST.gitlab-ci.yml)
- 시크릿 검색: [`Secret-Detection.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/Secret-Detection.gitlab-ci.yml)

위의 템플릿 중 하나를 사용하고 `_DISABLED` 변수를 사용하지만 `"true"` 이외의 값을 설정한 경우 16.0 릴리스 전에 파이프라인을 테스트하도록 권장합니다.

**업데이트**: 우리는 이전에 영향을 받는 템플릿의 `rules`을 업데이트하여 기본적으로 [병합 리퀘스트 파이프라인](https://docs.gitlab.com/ci/pipelines/merge_request_pipelines/)에서 실행되도록 공지했습니다. 그러나 호환성 문제[지원 중단 이슈에서 논의됨](https://gitlab.com/gitlab-org/gitlab/-/issues/388988#note_1372629948)으로 인해 GitLab 16.0에서 더 이상 이 변경을 수행하지 않을 것입니다. 우리는 여전히 위에서 설명한 대로 `_DISABLED` 변수에 대한 변경을 릴리스할 것입니다.

### 보안 보고서 스키마 버전 14.x.x {#security-report-schemas-version-14xx}

- GitLab 15.3에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/366477)를 참조하세요.

버전 14.x.x [보안 보고서 스키마](https://gitlab.com/gitlab-org/security-products/security-report-schemas)는 지원 중단되었습니다.

GitLab 15.8 이상에서 스키마 버전 14.x.x를 사용하는 [보안 보고서 스캐너 통합](https://docs.gitlab.com/development/integrations/secure/)은 파이프라인의 **보안** 탭에 지원 중단 경고를 표시합니다.

GitLab 16.0 이상에서는 기능이 제거됩니다. 스키마 버전 14.x.x를 사용하는 보안 보고서는 파이프라인의 **보안** 탭에서 오류를 발생시킵니다.

자세한 내용은 [보안 보고서 검증](https://docs.gitlab.com/user/application_security/#security-report-validation)을 참조하세요.

### Kubernetes용 GitLab 에이전트 구성의 Starboard 지시문 {#starboard-directive-in-the-configuration-of-the-gitlab-agent-for-kubernetes}

- GitLab 15.4에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/368828)를 참조하세요.

GitLab 컨테이너 스캔 기능은 더 이상 starboard가 설치되어야 합니다. 따라서 Kubernetes용 GitLab 에이전트 구성 파일에서 `starboard:` 지시문 사용은 이제 지원 중단되었으며 GitLab 16.0에서 제거될 예정입니다. 구성 파일을 업데이트하여 `container_scanning:` 지시문을 사용합니다.

### Windows Server 2004 및 20H2를 기반으로 한 GitLab Runner 이미지 게시 중지 {#stop-publishing-gitlab-runner-images-based-on-windows-server-2004-and-20h2}

- GitLab 16.0에서 발표
- GitLab 16.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab-runner/-/issues/31001)를 참조하세요.

GitLab 16.0부터 Windows Server 2004 및 20H2를 기반으로 한 GitLab Runner 이미지는 이러한 운영 체제가 지원 종료되었으므로 제공되지 않습니다.

### Praefect 사용자 지정 메트릭 엔드포인트 구성 지원 {#support-for-praefect-custom-metrics-endpoint-configuration}

- GitLab 15.9에서 발표
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/390266)를 참조하세요.

`prometheus_exclude_database_from_default_metrics` 구성 값 사용 지원은 GitLab 15.9에서 지원 중단되었으며 GitLab 16.0에서 제거됩니다. 이 구성 값을 사용하는 것은 성능 문제가 있으므로 제거하고 있습니다. 이 변경은 `/metrics`에서 다음 메트릭을 사용할 수 없게 됩니다:

- `gitaly_praefect_unavailable_repositories`.
- `gitaly_praefect_verification_queue_depth`.
- `gitaly_praefect_replication_queue_depth`.

이것은 `/db_metrics`를 스크랩하기 위해 메트릭 수집 대상을 업데이트해야 할 수 있습니다.

### Terraform 상태 이름에서 마침표(`.`) 지원이 기존 상태를 깰 수 있음 {#support-for-periods--in-terraform-state-names-might-break-existing-states}

- GitLab 15.7에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/385564)를 참조하세요.

이전에는 마침표가 포함된 Terraform 상태 이름이 지원되지 않았습니다. 그러나 여전히 해결 방법을 통해 마침표가 있는 상태 이름을 사용할 수 있었습니다.

GitLab 15.7 [마침표를 포함하는 상태 이름에 대한 전체 지원을 추가](https://docs.gitlab.com/user/infrastructure/iac/troubleshooting/#state-not-found-if-the-state-name-contains-a-period)합니다. 이러한 상태 이름을 처리하기 위해 해결 방법을 사용했으면 작업이 실패하거나 처음으로 Terraform을 실행한 것처럼 보일 수 있습니다.

이 문제를 해결하려면:

1. 마침표 및 이후의 모든 문자를 제외하여 상태 파일에 대한 모든 참조를 변경합니다.
   - 예를 들어 상태 이름이 `state.name`인 경우 모든 참조를 `state`로 변경합니다.
1. Terraform 명령을 실행합니다.

마침표를 포함한 전체 상태 이름을 사용하려면 [전체 상태 파일로 마이그레이션](https://docs.gitlab.com/user/infrastructure/iac/terraform_state/#migrate-to-a-gitlab-managed-terraform-state)합니다.

### Kubernetes용 에이전트에 대한 API는 더 이상 취소된 토큰을 반환하지 않음 {#the-api-no-longer-returns-revoked-tokens-for-the-agent-for-kubernetes}

- GitLab 15.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/382129)를 참조하세요.

현재 [클러스터 에이전트 API](https://docs.gitlab.com/api/cluster_agents/#list-tokens-for-an-agent) 엔드포인트에 대한 GET 요청은 취소된 토큰을 반환할 수 있습니다. GitLab 16.0에서 GET 요청은 취소된 토큰을 반환하지 않습니다.

이 엔드포인트에 대한 호출을 검토하고 취소된 토큰을 사용하지 않는지 확인해야 합니다.

이 변경은 다음 REST 및 GraphQL API 엔드포인트에 영향을 미칩니다:

- REST API:
  - [토큰 나열](https://docs.gitlab.com/api/cluster_agents/#list-tokens-for-an-agent)
  - [단일 토큰 가져오기](https://docs.gitlab.com/api/cluster_agents/#get-a-single-agent-token)
- GraphQL:
  - [`ClusterAgent.tokens`](https://docs.gitlab.com/api/graphql/reference/#clusteragenttokens)

### Phabricator 작업 가져오기는 지원 중단됨 {#the-phabricator-task-importer-is-deprecated}

- GitLab 15.7에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))

Phabricator 작업 가져오기는 지원 중단 중입니다. Phabricator 자체 프로젝트는 2021년 6월 1일부터 더 이상 활발하게 유지되지 않습니다. 이 도구를 사용한 가져오기를 관찰하지 않았습니다. GitLab의 관련 공개 이슈에 활동이 없었습니다.

### 최신 Terraform 템플릿이 현재 안정적인 템플릿을 덮어쓸 것입니다 {#the-latest-terraform-templates-will-overwrite-current-stable-templates}

- GitLab 15.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/386001)를 참조하세요.

모든 주요 GitLab 버전에서 안정적인 Terraform 템플릿을 현재 최신 템플릿으로 업데이트합니다. 이 변경은 [빠른 시작](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Terraform.gitlab-ci.yml) 및 [기본 템플릿](https://docs.gitlab.com/update/deprecations/#deprecate-terraform-cicd-templates)에 영향을 미칩니다.

새로운 템플릿에 기본 규칙이 포함되어 있으므로 업데이트로 인해 Terraform 파이프라인이 중단될 수 있습니다. 예를 들어 Terraform 작업이 다운스트림 파이프라인으로 트리거되는 경우 규칙이 GitLab 16.0에서 작업을 트리거하지 않습니다.

변경 사항에 맞추려면 `.gitlab-ci.yml` 파일에서 [`rules`](https://docs.gitlab.com/ci/yaml/#rules)을 조정해야 할 수 있습니다.

### 머지 리퀘스트에서 `/draft`/draft 빠른 작업 동작 전환 {#toggle-behavior-of-draft-quick-action-in-merge-requests}

- GitLab 15.4에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/365365)를 참조하세요.

빠른 작업을 통해 머지 리퀘스트의 초안 상태 전환 동작을 더 명확하게 하기 위해 `/draft`/draft 빠른 작업의 전환 동작을 지원 중단 및 제거하고 있습니다. GitLab 16.0 릴리스부터 `/draft`/draft는 머지 리퀘스트를 초안으로만 설정하고 새로운 `/ready`/ready 빠른 작업이 초안 상태를 제거하는 데 사용됩니다.

### `vulnerabilityFindingDismiss` 변경에서 `id` 필드 사용 {#use-of-id-field-in-vulnerabilityfindingdismiss-mutation}

- GitLab 15.3에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/367166)를 참조하세요.

`vulnerabilityFindingDismiss` GraphQL 변경을 사용하여 취약성 발견의 상태를 `Dismissed`로 설정할 수 있습니다. 이전에는 이 변경에서 `id` 필드를 사용하여 발견을 고유하게 식별했습니다. 그러나 이는 파이프라인 보안 탭에서 발견을 해제하는 데 작동하지 않았습니다. 따라서 `id` 필드를 식별자로 사용하는 것을 `uuid` 필드로 대신 사용하도록 삭제했습니다. 'uuid' 필드를 식별자로 사용하면 파이프라인 보안 탭에서 발견을 해제할 수 있습니다.

### 타사 컨테이너 레지스트리 사용은 지원 중단됨 {#use-of-third-party-container-registries-is-deprecated}

- GitLab 15.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/376216)를 참조하세요.

GitLab을 인증 엔드포인트로 사용하는 타사 컨테이너 레지스트리는 GitLab 15.8에서 지원 중단되었으며 [지원 종료](https://docs.gitlab.com/development/deprecation_guidelines/#terminology)는 GitLab 16.0으로 예정되어 있습니다. 이는 외부 레지스트리를 GitLab 사용자 인터페이스에 연결하여 컨테이너 이미지를 찾고, 보고, 삭제하는 GitLab Self-Managed의 사용자에게 영향을 미칩니다.

GitLab 컨테이너 레지스트리와 타사 컨테이너 레지스트리를 모두 지원하는 것은 유지 보수, 코드 품질 및 이전 버전과의 호환성에 어려움이 있으며 효율성을 유지하는 능력을 방해합니다. 결과적으로 앞으로는 이 기능을 지원하지 않을 것입니다.

이 변경은 파이프라인을 사용하여 외부 레지스트리에 컨테이너 이미지를 끌어오고 밀어내는 능력에는 영향을 미치지 않습니다.

GitLab.com용 새로운 [GitLab 컨테이너 레지스트리](https://gitlab.com/groups/gitlab-org/-/epics/5523) 버전을 출시한 이후 타사 컨테이너 레지스트리에서 사용할 수 없는 추가 기능을 구현하기 시작했습니다. 이러한 새로운 기능을 통해 [정리 정책](https://gitlab.com/groups/gitlab-org/-/epics/8379)과 같은 상당한 성능 개선을 달성했습니다. [새로운 기능](https://gitlab.com/groups/gitlab-org/-/epics/5136) 제공에 집중하고 있으며, 대부분 GitLab 컨테이너 레지스트리에서만 사용할 수 있는 기능이 필요합니다. 이 지원 중단을 통해 분산을 줄이고 장기적으로 사용자 불편함을 줄일 수 있으므로 더욱 강력한 통합 레지스트리 경험과 기능 세트를 제공하는 데 집중할 수 있습니다.

앞으로 GitLab 컨테이너 레지스트리에서만 사용할 수 있는 새로운 기능을 개발하고 출시하는 데 계속 투자할 것입니다.

### 경로 끝에 글로벌 ID가 있는 작업 항목 경로는 지원 중단됨 {#work-items-path-with-global-id-at-the-end-of-the-path-is-deprecated}

- GitLab 15.10에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/393836)를 참조하세요.

작업 항목 URL에서 글로벌 ID의 사용은 지원 중단됩니다. 앞으로는 내부 ID(IID)만 지원됩니다.

GitLab은 여러 작업 항목 유형을 지원하므로 `https://gitlab.com/gitlab-org/gitlab/-/work_items/<global_id>`와 같은 경로는 예를 들어 [작업](https://docs.gitlab.com/user/tasks/) 또는 [OKR](https://docs.gitlab.com/user/okrs/)을 표시할 수 있습니다.

GitLab 15.10에서 경로 끝에 쿼리 매개변수를 추가하여 내부 ID(IID)를 사용하기 위한 지원을 추가했습니다(`iid_path`) 형식: `https://gitlab.com/gitlab-org/gitlab/-/work_items/<iid>?iid_path=true`.

GitLab 16.0에서는 작업 항목 경로에서 글로벌 ID를 사용할 수 있는 기능을 제거합니다. 경로 끝의 번호는 쿼리 매개변수를 추가할 필요 없이 내부 ID(IID)로 간주됩니다. 다음 형식만 지원됩니다: `https://gitlab.com/gitlab-org/gitlab/-/work_items/<iid>`.

### `CI_BUILD_*` 사전 정의된 변수 {#ci_build_-predefined-variables}

- GitLab 14.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/352957)를 참조하세요.

`CI_BUILD_*`로 시작하는 사전 정의된 CI/CD 변수는 GitLab 9.0에서 지원 중단되었으며 GitLab 16.0에서 제거됩니다. 여전히 이러한 변수를 사용하는 경우 기능적으로 동일한 대체 [사전 정의된 변수](https://docs.gitlab.com/ci/variables/predefined_variables/)로 변경해야 합니다:

| 제거된 변수      | 대체 변수    |
| --------------------- |------------------------ |
| `CI_BUILD_BEFORE_SHA` | `CI_COMMIT_BEFORE_SHA`  |
| `CI_BUILD_ID`         | `CI_JOB_ID`             |
| `CI_BUILD_MANUAL`     | `CI_JOB_MANUAL`         |
| `CI_BUILD_NAME`       | `CI_JOB_NAME`           |
| `CI_BUILD_REF`        | `CI_COMMIT_SHA`         |
| `CI_BUILD_REF_NAME`   | `CI_COMMIT_REF_NAME`    |
| `CI_BUILD_REF_SLUG`   | `CI_COMMIT_REF_SLUG`    |
| `CI_BUILD_REPO`       | `CI_REPOSITORY_URL`     |
| `CI_BUILD_STAGE`      | `CI_JOB_STAGE`          |
| `CI_BUILD_TAG`        | `CI_COMMIT_TAG`         |
| `CI_BUILD_TOKEN`      | `CI_JOB_TOKEN`          |
| `CI_BUILD_TRIGGERED`  | `CI_PIPELINE_TRIGGERED` |

### `POST ci/lint` API 엔드포인트 지원 중단됨 {#post-cilint-api-endpoint-deprecated}

- GitLab 15.7에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/381669)를 참조하세요.

`POST ci/lint` API 엔드포인트는 15.7에서 지원 중단되었으며 16.0에서 제거됩니다. 이 엔드포인트는 CI/CD 구성 옵션의 전체 범위를 검증하지 않습니다. 대신 [`POST /projects/:id/ci/lint`](https://docs.gitlab.com/api/lint/#validate-a-ci-yaml-configuration-with-a-namespace)을 사용하세요. 이는 CI/CD 구성을 올바르게 검증합니다.

### DORA API의 `environment_tier` 매개변수 {#environment_tier-parameter-for-dora-api}

- GitLab 15.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/365939)를 참조하세요.

혼동과 중복을 피하기 위해 `environment_tier` 매개변수는 `environment_tiers` 매개변수를 위해 지원 중단됩니다. 새로운 `environment_tiers` 매개변수는 DORA API가 동시에 여러 계층에 대한 집계 데이터를 반환할 수 있도록 합니다. `environment_tier` 매개변수는 GitLab 16.0에서 제거됩니다.

### `PipelineSecurityReportFinding` GraphQL 유형의 `name` 필드 {#name-field-for-pipelinesecurityreportfinding-graphql-type}

- GitLab 15.1에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/346335)를 참조하세요.

이전에는 [`PipelineSecurityReportFinding` GraphQL 유형이 새로운 `title` 필드를 포함하도록 업데이트되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/issues/335372) 이 필드는 현재 `name` 필드의 별칭이므로 덜 구체적인 `name` 필드는 중복됩니다. `name` 필드는 GitLab 16.0에서 `PipelineSecurityReportFinding` 유형에서 제거됩니다.

### `started` 반복 상태 {#started-iteration-state}

- GitLab 14.8에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/334018)를 참조하세요.

`started` 반복 상태는 [반복 GraphQL API](https://docs.gitlab.com/api/graphql/reference/enums/#iterationstate) 및 [반복 REST API](https://docs.gitlab.com/api/iterations/#list-project-iterations)에서 지원 중단됩니다.

GraphQL API 버전은 GitLab 16.0에서 제거됩니다. 이 상태는 `current` 상태로 대체되고 있습니다(이미 사용 가능). 이는 마일스톤과 같은 다른 시간 기반 엔터티의 명명과 일치합니다.

다음 v5 REST API 버전까지 REST API 버전에서 `started` 상태에 대한 지원을 계속하는 것을 계획하고 있습니다.

### `vulnerabilityFindingDismiss` GraphQL 변경 {#vulnerabilityfindingdismiss-graphql-mutation}

- GitLab 15.5에서 발표됨
- GitLab 16.0에서 제거 ([주요 변경](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/375645)를 참조하세요.

`VulnerabilityFindingDismiss` GraphQL 변경은 지원 중단되고 GitLab 16.0에서 제거됩니다. 이 변경은 취약성 발견 ID가 사용자에게 제공되지 않았으므로 자주 사용되지 않았습니다(이 필드는 [15.3에서 지원 중단됨](https://docs.gitlab.com/update/deprecations/#use-of-id-field-in-vulnerabilityfindingdismiss-mutation)). 사용자는 대신 `VulnerabilityDismiss`을 사용하여 취약성 보고서의 취약성을 해제하거나 CI 파이프라인 보안 탭의 보안 발견을 위해 `SecurityFindingDismiss`을 사용해야 합니다.

## GitLab 15.11 {#gitlab-1511}

### openSUSE Leap 15.3 패키지 {#opensuse-leap-153-packages}

- GitLab 15.8에서 발표됨
- GitLab 15.11에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/7371)를 참조하세요.

openSUSE Leap 15.3에 대한 배포 지원 및 보안 업데이트는 [2022년 12월 종료됨](https://en.opensuse.org/Lifetime#Discontinued_distributions).

GitLab 15.7부터 openSUSE Leap 15.4용 패키지 제공을 시작했으며 15.11 마일스톤에서 openSUSE Leap 15.3용 패키지 제공을 중지합니다.

- openSUSE Leap 15.3 패키지에서 제공된 15.4 패키지로 전환하세요.

## GitLab 15.10 {#gitlab-1510}

### OpenStack Swift 및 Rackspace API를 사용한 자동 백업 업로드 {#automatic-backup-upload-using-openstack-swift-and-rackspace-apis}

- GitLab 15.8에서 발표됨
- GitLab 15.10에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/387976)를 참조하세요.

OpenStack Swift 및 Rackspace API를 사용하여 **원격 저장소에 백업 업로드** 지원을 지원 중단하고 있습니다. 이러한 API에 대한 지원은 더 이상 적극적으로 유지 관리되지 않는 타사 라이브러리에 따라 다르며 Ruby 3을 위해 업데이트되지 않았습니다. GitLab은 Ruby 2의 EOL 이전에 보안 패치를 최신으로 유지하기 위해 Ruby 3으로 전환하고 있습니다.

- OpenStack을 사용하는 경우 구성을 변경하여 Swift 대신 S3 API를 사용해야 합니다.
- Rackspace 저장소를 사용하는 경우 다른 공급자로 전환하거나 백업 작업이 완료된 후 백업 파일을 수동으로 업로드해야 합니다.

## GitLab 15.9 {#gitlab-159}

### 웹 IDE에서 라이브 미리보기를 더 이상 사용할 수 없음 {#live-preview-no-longer-available-in-the-web-ide}

- GitLab 15.8에서 발표됨
- GitLab 15.9에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/383889)를 참조하세요.

웹 IDE의 라이브 미리보기 기능은 정적 웹 애플리케이션의 클라이언트 측 미리보기를 제공하기 위한 것입니다. 그러나 복잡한 구성 단계와 지원되는 프로젝트 유형의 좁은 범위가 유틸리티를 제한했습니다. GitLab 15.7에서 웹 IDE 베타 버전이 도입되면서 이제 전체 서버 측 런타임 환경에 연결할 수 있습니다. 웹 IDE에 확장 설치를 위한 향후 지원을 통해 라이브 미리보기로 사용 가능한 것보다 더 고급 워크플로도 지원할 것입니다. GitLab 15.9부터 라이브 미리보기는 웹 IDE에서 더 이상 사용할 수 없습니다.

### `omniauth-authentiq` gem을 더 이상 사용할 수 없음 {#omniauth-authentiq-gem-no-longer-available}

- GitLab 15.9에서 발표
- GitLab 15.9에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/389452)를 참조하세요.

`omniauth-authentiq`은 GitLab의 일부인 OmniAuth 전략 gem입니다. 인증 서비스를 제공하는 회사인 Authentiq가 종료되었습니다. 따라서 gem이 제거되고 있습니다.

## GitLab 15.7 {#gitlab-157}

### `.gitlab-ci.yml`의 파일 유형 변수 확장 {#file-type-variable-expansion-in-gitlab-ciyml}

- GitLab 15.5에서 발표됨
- GitLab 15.7에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/29407)를 참조하세요.

이전에는 별칭 파일 변수를 참조하거나 적용한 변수가 `File` 유형 변수의 값을 확장했습니다. 예를 들어 파일 내용입니다. 이 동작은 일반적인 셸 변수 확장 규칙을 준수하지 않았기 때문에 잘못되었습니다. `File` 유형 변수에 저장된 비밀 또는 민감한 정보를 유출하기 위해 사용자는 변수를 입력 매개변수로 사용하여 $echo 명령을 실행할 수 있었습니다.

이 주요 변경 사항은 이 문제를 해결하지만 동작을 해결하는 사용자 워크플로를 방해할 수 있습니다. 이 변경을 통해 별칭 파일 변수를 참조하거나 적용하는 작업 변수 확장은 파일 내용과 같은 값 대신 `File` 유형 변수의 파일 이름 또는 경로로 확장됩니다.

### Flowdock 통합 {#flowdock-integration}

- GitLab 15.7에서 발표됨
- GitLab 15.7에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/379197)를 참조하세요.

2022년 12월 22일 현재 서비스가 2022년 8월 15일에 종료되었으므로 Flowdock 통합을 제거하고 있습니다.

## GitLab 15.6 {#gitlab-156}

### Git 리포지토리 저장소용 NFS {#nfs-for-git-repository-storage}

- GitLab 14.0에서 발표됨
- GitLab 15.6에서 제거

Gitaly Cluster의 일반 공급 가능성([GitLab 13.0에서 도입됨](https://about.gitlab.com/releases/2020/05/22/gitlab-13-0-released/))을 통해 GitLab 14.0에서 Git 리포지토리 저장소용 NFS에 대한 개발(버그 수정, 성능 개선 등)을 지원 중단했습니다. 14.x 전체에서 Git 리포지토리용 NFS에 대한 기술 지원을 계속 제공하지만 2022년 11월 22일에 NFS에 대한 모든 지원을 제거할 것입니다. 이는 원래 2022년 5월 22일로 계획되었지만 Gitaly Cluster의 지속적인 성숙도를 허용하기 위해 지원 중단 날짜를 연장하기로 선택했습니다. 자세한 정보는 공식 [지원 성명서](https://about.gitlab.com/support/statement-of-support/#gitaly-and-nfs)를 참조하세요.

Gitaly Cluster는 고객에게 엄청난 이점을 제공합니다:

- [변수 복제 요소](https://docs.gitlab.com/administration/gitaly/#replication-factor).
- [강력한 일관성](https://docs.gitlab.com/administration/gitaly/#strong-consistency).
- [분산 읽기 기능](https://docs.gitlab.com/administration/gitaly/#distributed-reads).

현재 Git 리포지토리에 NFS를 사용하는 고객이 [Gitaly Cluster로 마이그레이션](https://docs.gitlab.com/administration/gitaly/#migrate-to-gitaly-cluster)에 대한 설명서를 검토하여 마이그레이션을 계획할 것을 권장합니다.

## GitLab 15.4 {#gitlab-154}

### 번들 Grafana 지원 중단됨 {#bundled-grafana-deprecated}

- GitLab 15.3에서 발표됨
- GitLab 15.4에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/6972)를 참조하세요.

GitLab 15.4에서 번들 Grafana를 GitLab에서 유지 관리하는 Grafana 포크로 바꿀 것입니다.

Grafana의 [식별된 CVE](https://nvd.nist.gov/vuln/detail/CVE-2022-31107)가 있으므로 이 보안 취약성을 완화하기 위해 우리가 번들하던 이전 버전의 Grafana가 더 이상 장기 지원을 받지 않기 때문에 자체 포크로 전환해야 합니다.

이는 이전 버전의 Grafana와 호환성 문제를 야기할 것으로 예상되지 않습니다. 번들 버전을 사용할 때도, 외부 Grafana 인스턴스를 사용할 때도 아닙니다.

### SAST 분석기 통합 및 CI/CD 템플릿 변경 {#sast-analyzer-consolidation-and-cicd-template-changes}

- GitLab 14.8에서 발표됨
- GitLab 15.4에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/352554)를 참조하세요.

GitLab SAST는 다양한 [분석기](https://docs.gitlab.com/user/application_security/sast/analyzers/)를 사용하여 취약성에 대한 코드를 스캔합니다.

더 나은 사용자 경험을 제공하기 위한 장기 전략의 일환으로 GitLab SAST에서 사용되는 분석기의 수를 줄이고 있습니다. 분석기 세트를 간소화하면 더 빠른 반복, 더 나은 결과 및 더 큰 효율성(대부분의 경우 CI 러너 사용 감소)을 가능하게 합니다.

GitLab 15.4에서 GitLab SAST는 더 이상 다음 분석기를 사용하지 않습니다:

- [ESLint](https://gitlab.com/gitlab-org/security-products/analyzers/eslint) (JavaScript, TypeScript, React)
- [Gosec](https://gitlab.com/gitlab-org/security-products/analyzers/gosec) (Go)
- [Bandit](https://gitlab.com/gitlab-org/security-products/analyzers/bandit) (Python)

> [!note]
> 이 변경은 원래 GitLab 15.0으로 계획되었으며 GitLab 15.4로 연기되었습니다.

이러한 분석기는 [GitLab 관리 SAST CI/CD 템플릿](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/SAST.gitlab-ci.yml)에서 제거되고 [Semgrep 기반 분석기](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep)로 대체됩니다. 즉시 보안 업데이트만 받습니다. 다른 정기적인 개선 또는 업데이트는 보장되지 않습니다. 이러한 분석기가 지원 종료에 도달한 후에는 추가 업데이트가 제공되지 않습니다. 우리는 이러한 분석기에 대해 이전에 게시된 컨테이너 이미지를 삭제하지 않을 것입니다. 그러한 변경은 지원 중단, 제거 또는 주요 변경 공지로 발표될 것입니다.

또한 [SpotBugs](https://gitlab.com/gitlab-org/security-products/analyzers/spotbugs) 분석기에서 Java를 제거하고 [Semgrep 기반 분석기](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep)로 대체합니다. 이 변경으로 인해 Java 코드 검사가 간단해집니다. 컴파일이 더 이상 필요하지 않습니다. 이 변경은 [GitLab 관리 SAST CI/CD 템플릿](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/SAST.gitlab-ci.yml)의 자동 언어 감지 부분에 반영됩니다. SpotBugs 기반 분석기는 Groovy, Kotlin 및 Scala를 계속 처리합니다.

더 이상 사용되지 않는 분석기 중 하나에서 취약성 발견을 이미 해제한 경우 대체 분석기에서 이전 해제를 존중하려고 시도합니다. 시스템 동작은 다음에 따라 달라집니다:

- 이전에 Semgrep 기반 분석기를 실행에서 제외했는지 여부입니다.
- 프로젝트의 취약성 보고서에 표시된 취약성을 먼저 발견한 분석기입니다.

[취약성 변환 문서](https://docs.gitlab.com/user/application_security/sast/analyzers/#vulnerability-translation)를 참조하여 자세한 내용을 알아보세요.

영향을 받는 분석기에 커스터마이징을 적용했거나 현재 파이프라인에서 Semgrep 분석기를 비활성화하는 경우 [이 변경에 대한 지원 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/352554#breaking-change)에 자세히 설명된 대로 조치를 취해야 합니다.

## GitLab 15.3 {#gitlab-153}

### 상태별 취약성 보고서 정렬 {#vulnerability-report-sort-by-state}

- GitLab 15.0에서 공지
- GitLab 15.3에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/360516)를 참조하세요.

GitLab 14.10에서 기본 데이터 모델 리팩터링으로 인해 `State` 열별로 취약성 보고서를 정렬하는 기능이 비활성화되고 기능 플래그 뒤에 배치되었습니다. 이 값별로 정렬하기 위해 추가 리팩터링이 필요하므로 기능 플래그는 기본적으로 꺼진 상태로 유지되었습니다. 정렬을 위해 `State` 열의 사용이 매우 적으므로 코드베이스를 간소화하고 원치 않는 성능 저하를 방지하기 위해 기능 플래그를 대신 제거합니다.

### 도구별 취약성 보고서 정렬 {#vulnerability-report-sort-by-tool}

- GitLab 15.1에서 발표됨
- GitLab 15.3에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/362962)를 참조하세요.

GitLab 14.10에서 기본 데이터 모델 리팩터링으로 인해 `Tool` 열(검사 유형)별로 취약성 보고서를 정렬하는 기능이 비활성화되고 기능 플래그 뒤에 배치되었습니다. 이 값별로 정렬하기 위해 추가 리팩터링이 필요하므로 기능 플래그는 기본적으로 꺼진 상태로 유지되었습니다. 정렬을 위해 `Tool` 열의 사용이 매우 적으므로 GitLab 15.3에서 코드베이스를 간소화하고 원치 않는 성능 저하를 방지하기 위해 기능 플래그를 대신 제거합니다.

## GitLab 15.1 {#gitlab-151}

### Debian 9에 대한 지원 중단 {#deprecate-support-for-debian-9}

- GitLab 14.9에서 발표됨
- GitLab 15.1에서 제거

[Debian 9 Stretch에 대한 장기 서비스 및 지원(LTSS)은 2022년 7월에 종료됨](https://wiki.debian.org/LTS). 따라서 GitLab 패키지에 대해 Debian 9 배포를 더 이상 지원하지 않습니다. 사용자는 Debian 10 또는 Debian 11로 업그레이드할 수 있습니다.

## GitLab 15.0 {#gitlab-150}

### 리포지토리 푸시 이벤트의 감사 이벤트 {#audit-events-for-repository-push-events}

- GitLab 14.3에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/337993)를 참조하세요.

**리포지토리 이벤트**에 대한 감사 이벤트는 이제 지원 중단되었으며 GitLab 15.0에서 제거됩니다.

이러한 이벤트는 항상 기본적으로 비활성화되어 있었고 기능 플래그로 수동으로 활성화해야 했습니다. 이를 활성화하면 너무 많은 이벤트가 생성되어 GitLab 인스턴스의 속도가 크게 저하될 수 있습니다. 이러한 이유로 제거됩니다.

### 개체 저장소의 백그라운드 업로드 {#background-upload-for-object-storage}

- GitLab 14.9에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/26600)를 참조하세요.

[개체 저장소 기능](https://docs.gitlab.com/administration/object_storage/)의 전반적인 복잡성과 유지 보수 부담을 줄이기 위해 파일을 업로드하는 데 `background_upload`을 사용하는 지원은 지원 중단되었으며 GitLab 15.0에서 완전히 제거될 것입니다. [15.0 특정 변경](https://docs.gitlab.com/omnibus/update/gitlab_15_changes/)을 검토하여 [개체 저장소에 대해 제거된 백그라운드 업로드 설정](https://docs.gitlab.com/omnibus/update/gitlab_15_changes/#removed-background-uploads-settings-for-object-storage)을 확인하세요.

이는 개체 저장소 공급자의 작은 하위 집합에 영향을 미칩니다:

- **OpenStack** OpenStack을 사용하는 고객은 Swift 대신 S3 API를 사용하도록 구성을 변경해야 합니다.
- **RackSpace** RackSpace 기반 개체 저장소를 사용하는 고객은 다른 공급자로 데이터를 마이그레이션해야 합니다.

GitLab은 영향을 받는 고객의 마이그레이션을 지원하기 위한 추가 지침을 게시할 것입니다.

### CI/CD 작업 이름 길이 제한 {#cicd-job-name-length-limit}

- GitLab 14.6에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/342800)를 참조하세요.

GitLab 15.0에서 CI/CD 작업 이름의 문자 수를 255자로 제한하려고 합니다. 255자 제한을 초과하는 작업 이름이 있는 모든 파이프라인은 15.0 릴리스 후에 작동하지 않습니다.

### 인스턴스(공유) 러너를 프로젝트(특정) 러너로 변경 {#changing-an-instance-shared-runner-to-a-project-specific-runner}

- GitLab 14.5에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/345347)를 참조하세요.

GitLab 15.0에서는 더 이상 인스턴스(공유) 러너를 프로젝트(특정) 러너로 변경할 수 없습니다.

사용자는 종종 실수로 인스턴스 러너를 프로젝트 러너로 변경하고 다시 변경할 수 없습니다. GitLab은 보안상의 이유로 프로젝트 러너를 공유 러너로 변경할 수 없습니다. 한 프로젝트용의 러너가 전체 인스턴스에 대한 작업을 실행하도록 설정될 수 있습니다.

여러 프로젝트에 대한 러너를 추가해야 하는 관리자는 한 프로젝트에 대한 러너를 등록한 다음 관리 보기로 이동하여 추가 프로젝트를 선택할 수 있습니다.

### 컨테이너 네트워크 및 호스트 보안 {#container-network-and-host-security}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))

GitLab 컨테이너 네트워크 보안 및 컨테이너 호스트 보안 범주와 관련된 모든 기능은 GitLab 14.8에서 지원 중단되었으며 GitLab 15.0에서 제거될 예정입니다. 이 기능의 대체 기능이 필요한 사용자는 GitLab 외부에서 설치하고 관리할 수 있는 잠재적인 솔루션으로 다음 오픈 소스 프로젝트를 평가할 것을 권장합니다: [AppArmor](https://gitlab.com/apparmor/apparmor), [Cilium](https://github.com/cilium/cilium), [Falco](https://github.com/falcosecurity/falco), [FluentD](https://github.com/fluent/fluentd), [Pod 보안 승인](https://kubernetes.io/docs/concepts/security/pod-security-admission/).

이러한 기술을 GitLab에 통합하려면 [클러스터 관리 프로젝트 템플릿](https://docs.gitlab.com/user/clusters/management_project_template/)의 복사본에 원하는 Helm 차트를 추가하세요. 이 Helm 차트를 프로덕션에 배포하려면 GitLab [CI/CD](https://docs.gitlab.com/user/clusters/agent/ci_cd_workflow/)를 통해 명령을 호출하세요.

이 변경의 일환으로 다음과 같은 특정 기능이 GitLab 내에서 지원 중단되었으며 GitLab 15.0에서 제거될 예정입니다:

- **보안 및 컴플라이언스** > **위협 모니터링** 페이지.
- **보안 및 컴플라이언스** > **정책** 페이지에 있는 `Network Policy` 보안 정책 유형.
- GitLab을 통해 다음 기술과의 통합을 관리하는 기능: AppArmor, Cilium, Falco, FluentD 및 Pod 보안 정책.
- 위의 기능과 관련된 모든 API입니다.

추가 컨텍스트를 위해 또는 이 변경에 대한 피드백을 제공하려면 공개 [지원 중단 이슈](https://gitlab.com/groups/gitlab-org/-/epics/7476)를 참조하세요.

### 14.0.0 이하의 컨테이너 검사 스키마 {#container-scanning-schemas-below-1400}

- GitLab 14.7에서 공지
- GitLab 15.0에서 제거

[컨테이너 검사 보고서 스키마](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/releases) 버전 14.0.0 이전은 GitLab 15.0에서 더 이상 지원되지 않습니다. 보고서에 선언된 스키마 버전에 대해 검증에 통과하지 못하는 보고서는 GitLab 15.0에서도 더 이상 지원되지 않습니다.

파이프라인 작업 아티팩트로 컨테이너 검사 보안 보고서를 출력하여 [GitLab과 통합되는](https://docs.gitlab.com/development/integrations/secure/#report) 타사 도구가 영향을 받습니다. 모든 출력 보고서가 최소 버전 14.0.0의 올바른 스키마를 준수하는지 확인해야 합니다. 더 낮은 버전이거나 선언된 스키마 버전에 대해 검증에 실패하는 보고서는 처리되지 않으며 취약성 발견이 MR, 파이프라인 또는 취약성 보고서에 표시되지 않습니다.

전환을 돕기 위해 GitLab 14.10부터 비호환 보고서가 취약성 보고서에 [경고](https://gitlab.com/gitlab-org/gitlab/-/issues/335789#note_672853791)를 표시합니다.

### 14.0.0 이하의 커버리지 안내 퍼징 스키마 {#coverage-guided-fuzzing-schemas-below-1400}

- GitLab 14.7에서 공지
- GitLab 15.0에서 제거

[커버리지 안내 퍼징 보고서 스키마](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/releases) 버전 14.0.0 이하는 GitLab 15.0에서 더 이상 지원되지 않습니다. 보고서에 선언된 스키마 버전에 대해 검증에 통과하지 못하는 보고서는 GitLab 15.0에서도 더 이상 지원되지 않습니다.

파이프라인 작업 아티팩트로 커버리지 안내 퍼징 보안 보고서를 출력하여 [GitLab과 통합되는](https://docs.gitlab.com/development/integrations/secure/#report) 타사 도구가 영향을 받습니다. 모든 출력 보고서가 최소 버전 14.0.0의 올바른 스키마를 준수하는지 확인해야 합니다. 더 낮은 버전이거나 선언된 스키마 버전에 대해 검증에 실패하는 보고서는 처리되지 않으며 취약성 발견이 MR, 파이프라인 또는 취약성 보고서에 표시되지 않습니다.

전환을 돕기 위해 GitLab 14.10부터 비호환 보고서가 취약성 보고서에 [경고](https://gitlab.com/gitlab-org/gitlab/-/issues/335789#note_672853791)를 표시합니다.

### 14.0.0 이하의 DAST 스키마 {#dast-schemas-below-1400}

- GitLab 14.7에서 공지
- GitLab 15.0에서 제거

[DAST 보고서 스키마](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/releases) 버전 14.0.0 이전은 GitLab 15.0에서 더 이상 지원되지 않습니다. 보고서에 선언된 스키마 버전에 대해 검증에 통과하지 못하는 보고서는 GitLab 15.0부터 더 이상 지원되지 않습니다.

파이프라인 작업 아티팩트로 DAST 보안 보고서를 출력하여 [GitLab과 통합되는](https://docs.gitlab.com/development/integrations/secure/#report) 타사 도구가 영향을 받습니다. 모든 출력 보고서가 최소 버전 14.0.0의 올바른 스키마를 준수하는지 확인해야 합니다. 더 낮은 버전이거나 선언된 스키마 버전에 대해 검증에 실패하는 보고서는 처리되지 않으며 취약성 발견이 MR, 파이프라인 또는 취약성 보고서에 표시되지 않습니다.

전환을 돕기 위해 GitLab 14.10부터 비호환 보고서로 인해 [경고가 취약성 보고서에 표시](https://gitlab.com/gitlab-org/gitlab/-/issues/335789#note_672853791)됩니다.

### 종속성 검사 Python 3.9 및 3.6 이미지 지원 중단 {#dependency-scanning-python-39-and-36-image-deprecation}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/334060)를 참조하세요.

Python 프로젝트에 대한 종속성 검사를 사용하는 경우 Python 3.6을 사용하는 기본 `gemnasium-python:2` 이미지 및 Python 3.9를 사용하는 사용자 지정 `gemnasium-python:2-python-3.9` 이미지를 지원 중단하고 있습니다. GitLab 15.0부터의 새로운 기본 이미지는 [지원되는 버전](https://endoflife.date/python)이고 3.6은 [더 이상 지원되지 않으므로](https://endoflife.date/python) Python 3.9용입니다.

Python 3.9 또는 3.9 호환 프로젝트를 사용하는 사용자는 조치를 취할 필요가 없으며 종속성 검사는 GitLab 15.0에서 작동하기 시작해야 합니다. 지금 새 컨테이너를 테스트하고 싶다면 이 컨테이너(15.0에서 제거될 예정)를 사용하여 프로젝트에서 테스트 파이프라인을 실행하세요. Python 3.9 이미지를 사용하세요:

```yaml
gemnasium-python-dependency_scanning:
  image:
    name: registry.gitlab.com/gitlab-org/security-products/analyzers/gemnasium-python:2-python-3.9
```

Python 3.6을 사용하는 사용자의 경우 GitLab 15.0부터는 더 이상 종속성 검사의 기본 템플릿을 사용할 수 없습니다. 더 이상 사용되지 않는 `gemnasium-python:2` 분석기 이미지를 사용하도록 전환해야 합니다. 이 경우 영향을 받으면 [이 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/351503)에 댓글을 달아 필요한 경우 제거를 연장할 수 있습니다.

3.9 특수 예외 이미지를 사용하는 사용자의 경우 기본값을 대신 사용해야 하며 컨테이너를 더 이상 재정의하지 않아야 합니다. 3.9 특수 예외 이미지를 사용하고 있는지 확인하려면 다음 참조에 대해 `.gitlab-ci.yml` 파일을 확인하세요:

```yaml
gemnasium-python-dependency_scanning:
  image:
    name: registry.gitlab.com/gitlab-org/security-products/analyzers/gemnasium-python:2-python-3.9
```

### 종속성 검사 기본 Java 버전이 17로 변경됨 {#dependency-scanning-default-java-version-changed-to-17}

- GitLab 14.10에서 발표
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))

GitLab 15.0에서 종속성 검사의 경우 스캐너가 예상하는 Java의 기본 버전이 11에서 17로 업데이트됩니다. Java 17은 [최신 장기 지원(LTS) 버전](https://en.wikipedia.org/wiki/Java_version_history)입니다. 종속성 검사는 동일한 [범위의 버전(8, 11, 13, 14, 15, 16, 17)](https://docs.gitlab.com/user/application_security/dependency_scanning/#supported-languages-and-package-managers)을 계속 지원하며 기본 버전만 변경됩니다. 프로젝트에서 Java 11의 이전 기본값을 사용하는 경우 [`DS_Java_Version` 변수를 설정하여 일치](https://docs.gitlab.com/user/application_security/dependency_scanning/#configuring-specific-analyzers-used-by-dependency-scanning)하는지 확인하세요.

### 14.0.0 이하의 종속성 검사 스키마 {#dependency-scanning-schemas-below-1400}

- GitLab 14.7에서 공지
- GitLab 15.0에서 제거

[종속성 검사 보고서 스키마](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/releases) 버전 14.0.0 이전은 GitLab 15.0에서 더 이상 지원되지 않습니다. 보고서에 선언된 스키마 버전에 대해 검증에 통과하지 못하는 보고서는 GitLab 15.0부터 더 이상 지원되지 않습니다.

파이프라인 작업 아티팩트로 종속성 검사 보안 보고서를 출력하여 [GitLab과 통합되는](https://docs.gitlab.com/development/integrations/secure/#report) 타사 도구가 영향을 받습니다. 모든 출력 보고서가 최소 버전 14.0.0의 올바른 스키마를 준수하는지 확인해야 합니다. 더 낮은 버전이거나 선언된 스키마 버전에 대해 검증에 실패하는 보고서는 처리되지 않으며 취약성 발견이 MR, 파이프라인 또는 취약성 보고서에 표시되지 않습니다.

전환을 돕기 위해 GitLab 14.10부터 비호환 보고서로 인해 [경고가 취약성 보고서에 표시](https://gitlab.com/gitlab-org/gitlab/-/issues/335789#note_672853791)됩니다.

### Geo 관리 UI 경로 지원 중단 {#deprecate-geo-admin-ui-routes}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/351345)를 참조하세요.

GitLab 13.0에서 Geo 관리 UI의 새로운 프로젝트 및 디자인 복제 세부정보 경로를 도입했습니다. 이러한 경로는 `/admin/geo/replication/projects` 및 `/admin/geo/replication/designs`입니다. 레거시 경로를 유지하고 새 경로로 리디렉션했습니다. GitLab 15.0에서는 레거시 경로 `/admin/geo/projects` 및 `/admin/geo/designs`에 대한 지원을 제거합니다. 레거시 경로를 사용할 수 있는 책갈피 또는 스크립트를 업데이트하세요.

### 사용자 지정 Geo:db:\* Rake 작업 지원 중단 {#deprecate-custom-geodb-rake-tasks}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/351945)를 참조하세요.

GitLab 14.8에서는 [`geo:db:*` Rake 작업을 기본 제공 작업으로 대체](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/77269/diffs)하고 있으며 이는 이제 [Geo 추적 데이터베이스를 Rails' 6 다중 데이터베이스 지원으로 전환](https://gitlab.com/groups/gitlab-org/-/epics/6458) 후 가능합니다. 다음 `geo:db:*` 작업이 해당 `db:*:geo` 작업으로 대체됩니다:

- `geo:db:drop` -> `db:drop:geo`
- `geo:db:create` -> `db:create:geo`
- `geo:db:setup` -> `db:setup:geo`
- `geo:db:migrate` -> `db:migrate:geo`
- `geo:db:rollback` -> `db:rollback:geo`
- `geo:db:version` -> `db:version:geo`
- `geo:db:reset` -> `db:reset:geo`
- `geo:db:seed` -> `db:seed:geo`
- `geo:schema:load:geo` -> `db:schema:load:geo`
- `geo:db:schema:dump` -> `db:schema:dump:geo`
- `geo:db:migrate:up` -> `db:migrate:up:geo`
- `geo:db:migrate:down` -> `db:migrate:down:geo`
- `geo:db:migrate:redo` -> `db:migrate:redo:geo`
- `geo:db:migrate:status` -> `db:migrate:status:geo`
- `geo:db:test:prepare` -> `db:test:prepare:geo`
- `geo:db:test:load` -> `db:test:load:geo`
- `geo:db:test:purge` -> `db:test:purge:geo`

### 기능 플래그 PUSH_RULES_SUPERSEDE_CODE_OWNERS 지원 중단 {#deprecate-feature-flag-push_rules_supersede_code_owners}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/262019)를 참조하세요.

기능 플래그 `PUSH_RULES_SUPERSEDE_CODE_OWNERS`은 GitLab 15.0에서 제거되고 있습니다. 제거되면 푸시 규칙이 코드 소유자를 우선합니다. 코드 소유자 승인이 필요한 경우에도 특정 사용자가 코드를 푸시할 수 있도록 명시적으로 허용하는 푸시 규칙은 코드 소유자 설정을 무시합니다.

### Elasticsearch 6.8 {#elasticsearch-68}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/350275)를 참조하세요.

Elasticsearch 6.8은 GitLab 14.8에서 지원 중단되었으며 GitLab 15.0에서 제거될 예정입니다. Elasticsearch 6.8을 사용하는 고객은 GitLab 15.0으로 업그레이드하기 전에 Elasticsearch 버전을 7.x로 업그레이드해야 합니다. 모든 Elasticsearch 개선 사항을 활용하려면 최신 버전의 Elasticsearch 7을 사용하는 것이 좋습니다.

Elasticsearch 6.8은 또한 우리가 [GitLab 15.0에서 지원할 계획인](https://gitlab.com/gitlab-org/gitlab/-/issues/327560) Amazon OpenSearch와 호환되지 않습니다.

### 보안 보고서 스키마의 강제 검증 {#enforced-validation-of-security-report-schemas}

- GitLab 14.7에서 공지
- GitLab 15.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/groups/gitlab-org/-/epics/6968)를 참조하세요.

[보안 보고서 스키마](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/releases) 버전 14.0.0 이전은 GitLab 15.0에서 더 이상 지원되지 않습니다. 보고서에 선언된 스키마 버전에 대해 검증에 통과하지 못하는 보고서는 GitLab 15.0에서도 더 이상 지원되지 않습니다.

파이프라인 작업 아티팩트로 보안 보고서를 출력하여 [GitLab과 통합되는](https://docs.gitlab.com/development/integrations/secure/#report) 보안 도구가 영향을 받습니다. 모든 출력 보고서가 최소 버전 14.0.0의 올바른 스키마를 준수하는지 확인해야 합니다. 더 낮은 버전이거나 선언된 스키마 버전에 대해 검증에 실패하는 보고서는 처리되지 않으며 취약성 발견이 MR, 파이프라인 또는 취약성 보고서에 표시되지 않습니다.

전환을 돕기 위해 GitLab 14.10부터 비호환 보고서가 취약성 보고서에 [경고](https://gitlab.com/gitlab-org/gitlab/-/issues/335789#note_672853791)를 표시합니다.

### 외부 상태 확인 API 주요 변경 사항 {#external-status-check-api-breaking-changes}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))

[외부 상태 확인 API](https://docs.gitlab.com/api/status_checks/)는 원래 상태 확인을 통과로 표시하기 위해 기본값 요청으로 지나치는 것을 지원하도록 구현되었습니다. 기본값 요청은 이제 지원 중단되었습니다. 특히 다음은 지원 중단되었습니다:

- `status` 필드가 포함되지 않은 요청.
- `status` 필드가 `approved`로 설정된 요청.

GitLab 15.0부터 상태 확인은 `status` 필드가 있고 `passed`로 설정된 경우에만 통과 상태로 업데이트됩니다. 다음 요청:

- `status` 필드를 포함하지 않는 요청이 `422` 오류로 거부됩니다. 자세한 내용은 [관련 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/338827)를 참조하세요.
- `passed` 이외의 다른 값을 포함하면 상태 확인이 실패합니다. 자세한 내용은 [관련 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/339039)를 참조하세요.

이 변경과 일치시키기 위해 외부 상태 확인을 나열하기 위한 API 호출은 통과한 상태 확인의 경우 `approved` 대신 `passed` 값을 반환합니다.

### 데몬으로 실행되는 GitLab Pages {#gitlab-pages-running-as-daemon}

- GitLab 14.9에서 발표됨
- GitLab 15.0에서 제거

15.0에서는 GitLab Pages의 데몬 모드 지원이 제거됩니다.

### GitLab 서버리스 {#gitlab-serverless}

- GitLab 14.3에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/groups/gitlab-org/configure/-/epics/6)를 참조하세요.

GitLab Serverless는 자동 배포 및 모니터링을 통해 Knative 기반 서버리스 개발을 지원하는 기능 세트입니다.

사용자들과 실제로 공감하지 못했기 때문에 GitLab 서버리스 기능을 제거하기로 결정했습니다. 더욱이 Kubernetes 및 Knative의 지속적인 개발을 고려할 때 현재 구현은 최신 버전에서도 작동하지 않습니다.

### 라이센스 준수의 Godep 지원 {#godep-support-in-license-compliance}

- GitLab 14.7에서 공지
- GitLab 15.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/327057)를 참조하세요.

Go용 Godep 종속성 관리자는 2020년에 Go에서 지원 중단되었으며 Go 모듈로 대체되었습니다. 유지 보수 비용을 줄이기 위해 14.7부터 Godep 프로젝트에 대한 라이센스 준수를 지원 중단하고 GitLab 15.0에서 제거합니다.

### GraphQL ID 및 GlobalID 호환성 {#graphql-id-and-globalid-compatibility}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/257883)를 참조하세요.

우리는 GraphQL 프로세서에 대한 표준이 아닌 확장을 제거하고 있으며, 이는 이전 버전과의 호환성을 위해 추가했습니다. 이 확장은 GraphQL 쿼리의 검증을 수정하여 일반적으로 거부되는 인수에 `ID` 유형을 사용할 수 있도록 합니다. 일부 인수는 원래 `ID` 유형을 가졌습니다. 이것들은 특정 종류의 `ID`으로 변경되었습니다. 다음 중 하나를 수행하면 이 변경이 주요 변경 사항일 수 있습니다:

- GraphQL을 사용합니다.
- 쿼리 서명의 인수에 `ID` 유형을 사용합니다.

일부 필드 인수는 여전히 `ID` 유형을 가집니다. 이것들은 일반적으로 IID 값 또는 네임스페이스 경로입니다. 예는 `Query.project(fullPath: ID!)`입니다.

영향을 받는 필드 인수와 영향을 받지 않는 필드 인수의 목록은 [지원 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/352832)를 참조하세요.

GitLab 서버에서 가져온 스키마 데이터를 사용하여 쿼리를 로컬로 검증하여 이 변경이 사용자에게 영향을 미치는지 테스트할 수 있습니다. 관련 GitLab 인스턴스에 대한 GraphQL 탐색 도구를 사용하여 이를 수행할 수 있습니다. 예: `https://gitlab.com/-/graphql-explorer`.

예를 들어 다음 쿼리는 주요 변경을 설명합니다:

```graphql
# a query using the deprecated type of Query.issue(id:)
# WARNING: This will not work after GitLab 15.0
query($id: ID!) {
  deprecated: issue(id: $id) {
    title, description
  }
}
```

위의 쿼리는 `Query.issue(id:)`의 유형이 실제로 `IssueID!`이기 때문에 GitLab 15.0이 릴리스되면 작동하지 않습니다.

대신 다음 두 형식 중 하나를 사용해야 합니다:

```graphql
# This will continue to work
query($id: IssueID!) {
  a: issue(id: $id) {
    title, description
  }
  b: issue(id: "gid://gitlab/Issue/12345") {
    title, description
  }
}
```

이 쿼리는 지금 작동하며 GitLab 15.0 이후에도 계속 작동합니다. 서명에서 명명된 유형으로 `ID`을 사용하는 첫 번째 형식의 모든 쿼리를 서명의 올바른 적절한 유형을 사용하는 다른 두 형식 또는 인라인 인수 식을 사용하는 형식으로 변환해야 합니다.

### 패키지 설정에 대한 GraphQL 권한 변경 {#graphql-permissions-change-for-package-settings}

- GitLab 14.9에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))

GitLab 패키지 단계는 패키지 레지스트리, 컨테이너 레지스트리 및 종속성 프록시를 제공하여 모든 종속성을 GitLab을 사용하여 관리할 수 있도록 합니다. 이러한 각 제품 범주에는 API를 사용하여 조정할 수 있는 다양한 설정이 있습니다.

GraphQL의 권한 모델이 업데이트되고 있습니다. 15.0 이후 게스트, 리포터 및 개발자 역할의 사용자는 더 이상 다음 설정을 업데이트할 수 없습니다:

- [패키지 레지스트리 설정](https://docs.gitlab.com/api/graphql/reference/objects/#packagesettings)
- [컨테이너 레지스트리 정리 정책](https://docs.gitlab.com/api/graphql/reference/objects/#containerexpirationpolicy)
- [종속성 프록시 TTL 정책](https://docs.gitlab.com/api/graphql/reference/objects/#dependencyproxyimagettlgrouppolicy)
- [그룹에 대한 종속성 프록시 활성화](https://docs.gitlab.com/api/graphql/reference/objects/#dependencyproxysetting)

### GitLab Runner SSH 실행기에 필요한 알려진 호스트 {#known-host-required-for-gitlab-runner-ssh-executor}

- GitLab 14.5에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab-runner/-/issues/28192)를 참조하세요.

[GitLab 14.3](https://gitlab.com/gitlab-org/gitlab-runner/-/merge_requests/3074)에서 GitLab Runner `config.toml` 파일에 구성 설정을 추가했습니다. 이 설정인 [`[runners.ssh.disable_strict_host_key_checking]`](https://docs.gitlab.com/runner/executors/ssh/#security)는 SSH 실행기에서 엄격한 호스트 키 확인을 사용할지 여부를 제어합니다.

GitLab 15.0 이상에서 이 구성 옵션의 기본값이 `true`에서 `false`로 변경됩니다. 이는 GitLab Runner SSH 실행기를 사용할 때 엄격한 호스트 키 확인이 강제됨을 의미합니다.

### 라이센스 준수 API의 레거시 승인 상태 이름 {#legacy-approval-status-names-from-license-compliance-api}

- GitLab 14.6에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/335707)를 참조하세요.

라이센스 정책(`blacklisted`, `approved`)의 승인 상태에 대한 레거시 이름을 `managed_licenses` API에서 지원 중단했지만 여전히 API 쿼리 및 응답에 사용됩니다. 15.0에서 제거됩니다.

라이센스 준수 API를 사용하는 경우 `approved` 및 `blacklisted` 쿼리 매개변수 사용을 중단해야 합니다. 이제 `allowed` 및 `denied`입니다. 15.0에서 응답도 `approved` 및 `blacklisted`을 사용하지 않으므로 15.0 릴리스로 인해 중단되지 않도록 사용자 정의 도구를 조정하려면 이전 및 새로운 값을 모두 사용해야 합니다.

### 레거시 데이터베이스 구성 {#legacy-database-configuration}

- GitLab 14.3에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/338182)를 참조하세요.

`database.yml`에 있는 [GitLabs 데이터베이스](https://docs.gitlab.com/omnibus/settings/database/) 구성의 구문이 변경되고 있으며 레거시 형식은 지원 중단됩니다. 레거시 형식은 단일 PostgreSQL 어댑터를 사용하는 것을 지원했지만 새 형식은 여러 데이터베이스를 지원하도록 변경되고 있습니다. `main:` 데이터베이스를 첫 번째 구성 항목으로 정의해야 합니다.

이 지원 중단은 주로 GitLab을 소스에서 컴파일하는 사용자에게 영향을 미칩니다. Omnibus는 이 구성을 자동으로 처리하기 때문입니다.

### GitLab에 로깅 {#logging-in-gitlab}

- GitLab 14.7에서 공지
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/346485)를 참조하세요.

GitLab의 로깅 기능을 통해 사용자는 ELK 스택(Elasticsearch, Logstash 및 Kibana)을 설치하여 애플리케이션 로그를 집계하고 관리할 수 있습니다. 사용자는 GitLab에서 관련 로그를 검색할 수 있습니다. 그러나 Kubernetes 클러스터와 GitLab 관리 애플리케이션과의 인증서 기반 통합을 지원 중단한 이후 GitLab 내에서 로깅을 위한 권장 솔루션이 없습니다. [Opstrace를 GitLab과 통합](https://gitlab.com/groups/gitlab-org/-/epics/6976)하는 문제를 따라 자세히 알아볼 수 있습니다.

### `custom_hooks_dir` 설정을 GitLab Shell에서 Gitaly로 이동 {#move-custom_hooks_dir-setting-from-gitlab-shell-to-gitaly}

- GitLab 14.9에서 발표됨
- GitLab 15.0에서 제거

[`custom_hooks_dir`](https://docs.gitlab.com/administration/server_hooks/#create-a-global-server-hook-for-all-repositories) 설정이 이제 Gitaly에서 구성되며 GitLab 15.0에서 GitLab Shell에서 제거됩니다.

### OAuth 암시적 부여 {#oauth-implicit-grant}

- GitLab 14.0에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))

OAuth 암시적 부여 권한 부여 흐름은 다음 주요 릴리스인 GitLab 15.0에서 제거됩니다. OAuth 암시적 부여를 사용하는 모든 애플리케이션은 대체 [지원되는 OAuth 흐름](https://docs.gitlab.com/api/oauth2/)으로 전환해야 합니다.

### 만료 없는 OAuth 토큰 {#oauth-tokens-without-expiration}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))

기본적으로 모든 새 애플리케이션은 2시간 후에 액세스 토큰을 만료합니다. GitLab 14.2 이전에는 OAuth 액세스 토큰이 만료되지 않았습니다. GitLab 15.0에서 기존 토큰 중 아직 만료되지 않은 토큰에 대해 만료 시간이 자동으로 생성됩니다.

GitLab 15.0이 릴리스되기 전에 [만료 토큰 선택](https://docs.gitlab.com/integration/oauth_provider/#access-token-expiration)을 해야 합니다:

1. 응용 프로그램을 편집합니다.
1. **액세스 토큰 만료**를 선택하여 활성화하세요. 토큰을 해지하거나 만료되지 않습니다.

### OmniAuth Kerberos gem {#omniauth-kerberos-gem}

- GitLab 14.3에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/337384)를 참조하세요.

`omniauth-kerberos` gem은 다음 주요 릴리스인 GitLab 15.0에서 제거됩니다.

이 gem은 유지 관리되지 않았으며 사용량이 매우 적습니다. 따라서 이 인증 방법에 대한 지원을 제거할 계획이며 대신 Kerberos [SPNEGO](https://en.wikipedia.org/wiki/SPNEGO) 통합을 사용할 것을 권장합니다. [업그레이드 지침](https://docs.gitlab.com/integration/kerberos/#upgrading-from-password-based-to-ticket-based-kerberos-sign-ins)을 따라 `omniauth-kerberos` 통합에서 지원되는 통합으로 업그레이드할 수 있습니다.

Kerberos SPNEGO 통합은 지원 중단하지 않고 있으며 이전 암호 기반 Kerberos 통합만 지원 중단하고 있습니다.

### PAT 만료의 선택적 적용 {#optional-enforcement-of-pat-expiration}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/351962)를 참조하세요.

PAT 만료 적용을 해제하는 기능은 보안 관점에서 일반적이지 않습니다. 이러한 비일반적인 기능이 사용자에게 예기치 않은 동작을 초래할 수 있다는 우려가 생겼습니다. 보안 기능에서 예기치 않은 동작은 본질적으로 위험하므로 이 기능을 제거하기로 결정했습니다.

### SSH 만료의 선택 사항 적용 {#optional-enforcement-of-ssh-expiration}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/351963)를 참조하세요.

SSH 만료 적용을 해제하는 기능은 보안 관점에서 일반적이지 않습니다. 이러한 비일반적인 기능이 사용자에게 예기치 않은 동작을 초래할 수 있다는 우려가 생겼습니다. 보안 기능에서 예기치 않은 동작은 본질적으로 위험하므로 이 기능을 제거하기로 결정했습니다.

### Java 8용 기본 SAST 지원 {#out-of-the-box-sast-support-for-java-8}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/352549)를 참조하세요.

[GitLab SAST SpotBugs 분석기](https://gitlab.com/gitlab-org/security-products/analyzers/spotbugs)는 [Java, Scala, Groovy 및 Kotlin 코드](https://docs.gitlab.com/user/application_security/sast/#supported-languages-and-frameworks)에서 보안 취약성을 검사합니다. 기술적 이유로 분석기는 검사하기 전에 먼저 코드를 컴파일해야 합니다. [사전 컴파일 전략](https://docs.gitlab.com/user/application_security/sast/#pre-compilation)을 사용하지 않으면 분석기는 프로젝트의 코드를 자동으로 컴파일하려고 시도합니다.

GitLab 15.0 이전 버전에서는 분석기 이미지에 Java 8 및 Java 11 런타임이 포함되어 있어 컴파일을 용이하게 합니다.

GitLab 15.0에서 다음을 수행합니다:

- 이미지 크기를 줄이기 위해 분석기 이미지에서 Java 8을 제거합니다.
- Java 17로 컴파일하기 쉽게 하기 위해 분석기 이미지에 Java 17을 추가합니다.

분석기 환경에 Java 8이 있다고 의존하는 경우 [이 변경 사항에 대한 지원 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/352549#breaking-change)에 명시된 대로 조치를 취해야 합니다.

### 고급 검색 마이그레이션의 오래된 인덱스 {#outdated-indices-of-advanced-search-migrations}

- GitLab 14.10에서 발표
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/359133)를 참조하세요.

고급 검색 마이그레이션은 일반적으로 오랜 기간 동안 여러 코드 경로를 지원해야 하므로 안전하게 정리할 때 이를 정리하는 것이 중요합니다. GitLab 메이저 버전 업그레이드를 완전히 마이그레이션되지 않은 인덱스의 이전 버전 호환성을 제거하는 안전한 시간으로 사용합니다. 자세한 내용은 [업그레이드 설명서](https://docs.gitlab.com/update/#upgrading-to-a-new-major-version)를 참조하세요.

### 의사화화기 {#pseudonymizer}

- GitLab 14.7에서 공지
- GitLab 15.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/219952)를 참조하세요.

의사화화기 기능은 일반적으로 사용되지 않으며 큰 데이터베이스에서 프로덕션 문제를 야기할 수 있고 객체 스토리지 개발을 방해할 수 있습니다. 이제 이 기능은 지원 중단된 것으로 간주되며 GitLab 15.0에서 제거될 것입니다.

### `instanceStatisticsMeasurements` GraphQL 노드를 통해 사용 추세 조회 {#querying-usage-trends-via-the-instancestatisticsmeasurements-graphql-node}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/332323)를 참조하세요.

`instanceStatisticsMeasurements` GraphQL 노드는 13.10에서 `usageTrendsMeasurements`로 이름이 바뀌었으며 이전 필드 이름은 지원 중단된 것으로 표시되었습니다. 기존 GraphQL 쿼리를 수정하려면 `instanceStatisticsMeasurements`을(를) `usageTrendsMeasurements`로 바꾸세요.

### 요청 프로파일링 {#request-profiling}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/352488)를 참조하세요.

[요청 프로파일링](https://docs.gitlab.com/administration/monitoring/performance/)은 GitLab 14.8에서 지원 중단되었으며 GitLab 15.0에서 제거할 예정입니다.

우리는 [프로파일링 도구 통합](https://gitlab.com/groups/gitlab-org/-/epics/7327)을 진행 중이며 더 쉽게 접근할 수 있도록 만들고 있습니다. 우리는 [이 기능의 사용을 평가](https://gitlab.com/gitlab-org/gitlab/-/issues/350152)했으며 널리 사용되지 않고 있음을 발견했습니다. 또한 더 이상 적극적으로 유지되지 않는 몇 가지 타사 gem에 의존하며, 최신 버전의 Ruby로 업데이트되지 않았거나 큰 페이지 로드를 프로파일링할 때 자주 충돌합니다.

자세한 내용은 [지원 중단 이슈의 요약 섹션](https://gitlab.com/gitlab-org/gitlab/-/issues/352488#deprecation-summary)을 확인하세요.

### Premium 티어의 필수 파이프라인 구성 {#required-pipeline-configurations-in-premium-tier}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))

[필수 파이프라인 구성](https://docs.gitlab.com/administration/settings/continuous_integration/#required-pipeline-configuration-deprecated) 기능은 GitLab 14.8에서 Premium 고객을 위해 지원 중단되었으며 GitLab 15.0에서 제거할 예정입니다. 이 기능은 GitLab Ultimate 고객을 위해 지원 중단되지 않습니다.

기능을 GitLab Ultimate 티어로 이동하는 이 변경 사항은 기능이 주로 임원진의 요구에서 비롯되므로 당사의 기능이 가격 정책에 더 잘 맞도록 돕기 위한 것입니다.

이 변경 사항은 또한 GitLab이 다음의 다른 관련 Ultimate 티어 기능과의 계층화 전략에서 일관성을 유지하도록 도울 것입니다: [보안 정책](https://docs.gitlab.com/user/application_security/policies/) 및 [규정 준수 프레임워크 파이프라인](https://docs.gitlab.com/user/project/settings/#compliance-pipeline-configuration).

### Retire-JS 종속성 검사 도구 {#retire-js-dependency-scanning-tool}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/350510)를 참조하세요.

14.8부터 retire.js 작업은 종속성 검사에서 지원 중단되고 있습니다. 지원 중단되는 동안 CI/CD 템플릿에 계속 포함될 것입니다. 2022년 5월 22일 GitLab 15.0에서 종속성 검사에서 retire.js를 제거합니다. JavaScript 검사 기능은 Gemnasium에서 여전히 다루고 있으므로 영향을 받지 않습니다.

DS_EXCLUDED_ANALYZERS를 사용하여 retire.js를 명시적으로 제외한 경우 15.0에서 정리(참조 제거)해야 합니다. 파이프라인의 종속성 검사 구성을 `retire-js-dependency_scanning` 작업과 관련하여 사용자 정의한 경우 15.0의 제거 전에 gemnasium-dependency_scanning으로 전환하여 파이프라인이 실패하지 않도록 하려고 할 것입니다. DS_EXCLUDED_ANALYZERS를 사용하여 retire.js를 참조하지 않았거나 retire.js를 위해 특별히 템플릿을 사용자 정의하지 않은 경우 조치를 취할 필요가 없습니다.

### 14.0.0 이상의 SAST 스키마 {#sast-schemas-below-1400}

- GitLab 14.7에서 공지
- GitLab 15.0에서 제거

[SAST 보고서 스키마](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/releases) 버전 14.0.0 이상은 GitLab 15.0에서 더 이상 지원되지 않습니다. 보고서에 선언된 스키마 버전에 대해 검증에 통과하지 못하는 보고서는 GitLab 15.0부터 더 이상 지원되지 않습니다.

[GitLab과 통합하여 SAST 보안 보고서를 출력](https://docs.gitlab.com/development/integrations/secure/#report)하는 타사 도구는 파이프라인 작업 아티팩트로 영향을 받습니다. 모든 출력 보고서가 최소 버전 14.0.0의 올바른 스키마를 준수하는지 확인해야 합니다. 더 낮은 버전이거나 선언된 스키마 버전에 대해 검증에 실패하는 보고서는 처리되지 않으며 취약성 발견이 MR, 파이프라인 또는 취약성 보고서에 표시되지 않습니다.

전환을 돕기 위해 GitLab 14.10부터 비호환 보고서가 취약성 보고서에 [경고](https://gitlab.com/gitlab-org/gitlab/-/issues/335789#note_672853791)를 표시합니다.

### .NET 2.1용 SAST 지원 {#sast-support-for-net-21}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/352553)를 참조하세요.

GitLab SAST 보안 코드 스캔 분석기는 .NET 코드에서 보안 취약성을 검사합니다. 기술적 이유로 분석기는 먼저 코드를 빌드하여 검사해야 합니다.

GitLab 15.0 이전 버전에서 기본 분석기 이미지(버전 2)는 다음을 지원합니다:

- .NET 2.1
- .NET 3.0 및 .NET Core 3.0
- .NET Core 3.1
- .NET 5.0

GitLab 15.0에서 이 분석기의 기본 메이저 버전을 버전 2에서 버전 3으로 변경합니다. 이 변경 사항:

- [취약성의 심각도 값](https://gitlab.com/gitlab-org/gitlab/-/issues/350408)을 [다른 새로운 기능 및 개선 사항](https://gitlab.com/gitlab-org/security-products/analyzers/security-code-scan/-/blob/master/CHANGELOG.md)과 함께 추가합니다.
- .NET 2.1 지원을 제거합니다.
- .NET 6.0, Visual Studio 2019 및 Visual Studio 2022에 대한 지원을 추가합니다.

버전 3은 [GitLab 14.6에서 발표](https://about.gitlab.com/releases/2021/12/22/gitlab-14-6-released/#sast-support-for-net-6)되었으며 선택적 업그레이드로 제공되었습니다.

.NET 2.1 지원이 기본적으로 분석기 이미지에 있다고 의존하는 경우 [이 변경 사항에 대한 지원 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/352553#breaking-change)에 명시된 대로 조치를 취해야 합니다.

### 시크릿 검색 구성 변수 지원 중단됨 {#secret-detection-configuration-variables-deprecated}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/352565)를 참조하세요.

[GitLab 시크릿 검색을 사용자 정의](https://docs.gitlab.com/user/application_security/secret_detection/#customizing-settings)하기를 더 간단하고 안정적으로 만들기 위해 CI/CD 구성에서 이전에 설정할 수 있었던 일부 변수를 지원 중단하고 있습니다.

다음 변수는 현재 이력 검사에 대한 옵션을 사용자 정의할 수 있도록 허용하지만 [GitLab 관리 CI/CD 템플릿](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/Secret-Detection.gitlab-ci.yml)과 상호 작용하지 않아 이제 지원 중단됩니다:

- `SECRET_DETECTION_COMMIT_FROM`
- `SECRET_DETECTION_COMMIT_TO`
- `SECRET_DETECTION_COMMITS`
- `SECRET_DETECTION_COMMITS_FILE`

`SECRET_DETECTION_ENTROPY_LEVEL`은(는) 이전에 코드베이스의 문자열의 엔트로피 수준만 고려하는 규칙을 구성할 수 있도록 허용했으며 이제 지원 중단되었습니다. 이러한 유형의 엔트로피 전용 규칙은 수용할 수 없는 수의 잘못된 결과(거짓 양성)를 만들었으며 더 이상 지원되지 않습니다.

GitLab 15.0에서 시크릿 검색 [분석기](https://docs.gitlab.com/user/application_security/terminology/#analyzer)를 업데이트하여 이러한 지원 중단된 옵션을 무시합니다. 여전히 [`SECRET_DETECTION_HISTORIC_SCAN` CI/CD 변수](https://docs.gitlab.com/user/application_security/secret_detection/#available-cicd-variables)를 설정하여 커밋 이력의 이력 검사를 구성할 수 있습니다.

자세한 내용은 [이 변경 사항에 대한 지원 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/352565)를 참조하세요.

### 14.0.0 이상의 시크릿 검색 스키마 {#secret-detection-schemas-below-1400}

- GitLab 14.7에서 공지
- GitLab 15.0에서 제거

[시크릿 검색 보고서 스키마](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/releases) 버전 14.0.0 이상은 GitLab 15.0에서 더 이상 지원되지 않습니다. 보고서에 선언된 스키마 버전에 대해 검증에 통과하지 못하는 보고서는 GitLab 15.0부터 더 이상 지원되지 않습니다.

[GitLab과 통합하여 시크릿 검색 보안 보고서를 출력](https://docs.gitlab.com/development/integrations/secure/#report)하는 타사 도구는 파이프라인 작업 아티팩트로 영향을 받습니다. 모든 출력 보고서가 최소 버전 14.0.0의 올바른 스키마를 준수하는지 확인해야 합니다. 더 낮은 버전이거나 선언된 스키마 버전에 대해 검증에 실패하는 보고서는 처리되지 않으며 취약성 발견이 MR, 파이프라인 또는 취약성 보고서에 표시되지 않습니다.

전환을 돕기 위해 GitLab 14.10부터 비호환 보고서가 취약성 보고서에 [경고](https://gitlab.com/gitlab-org/gitlab/-/issues/335789#note_672853791)를 표시합니다.

### 보안 및 보호 분석기 이미지가 새로운 위치에 게시됨 {#secure-and-protect-analyzer-images-published-in-new-location}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/352564)를 참조하세요.

GitLab은 다양한 [분석기](https://docs.gitlab.com/user/application_security/terminology/#analyzer)를 사용하여 [보안 취약성을 검사](https://docs.gitlab.com/user/application_security/)합니다. 각 분석기는 컨테이너 이미지로 배포됩니다.

GitLab 14.8부터 새로운 GitLab 보안 및 보호 분석기 버전은 `registry.gitlab.com/security-products` 아래의 새 레지스트리 위치에 게시됩니다.

이 변경 사항을 반영하기 위해 [GitLab 관리 CI/CD 템플릿](https://gitlab.com/gitlab-org/gitlab/-/tree/master/lib/gitlab/ci/templates/Security)의 기본값을 업데이트합니다:

- 컨테이너 검사를 제외한 모든 분석기에 대해 변수 `SECURE_ANALYZERS_PREFIX`을(를) 새 이미지 레지스트리 위치로 업데이트합니다.
- 컨테이너 검사의 경우 기본 이미지 주소가 이미 업데이트되었습니다. 컨테이너 검사에 대한 `SECURE_ANALYZERS_PREFIX` 변수가 없습니다.

향후 릴리스에서 `registry.gitlab.com/gitlab-org/security-products/analyzers`에 이미지를 게시하지 않을 것입니다. 이 작업이 발생하면 이미지를 수동으로 끌어와 별도 레지스트리로 푸시하는 경우 조치를 취해야 합니다. 이는 일반적으로 [오프라인 배포](https://docs.gitlab.com/user/application_security/offline_deployments/)의 경우입니다. 그렇지 않으면 추가 업데이트를 받지 않습니다.

자세한 내용은 [지원 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/352564)를 참조하세요.

### 보안 및 보호 분석기 메이저 버전 업데이트 {#secure-and-protect-analyzer-major-version-update}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/350936)를 참조하세요.

보안 및 보호 스테이지는 GitLab 15.0 릴리스와 함께 분석기의 메이저 버전을 함께 범프합니다. 이 메이저 범프는 분석기의 명확한 구분을 가능하게 합니다:

- 2022년 5월 22일 이전에 릴리스된 것들로, _엄격한 스키마 유효성 검사의 대상이 아닌_ 보고서를 생성합니다.
- 2022년 5월 22일 이후에 릴리스된 것들로, _엄격한 스키마 유효성 검사의 대상이 되는_ 보고서를 생성합니다.

기본 포함 템플릿을 사용하지 않거나 분석기 버전을 고정한 경우 고정된 버전을 제거하거나 최신 메이저 버전을 업데이트하기 위해 CI/CD 작업 정의를 업데이트해야 합니다. GitLab 12.0-14.10 사용자는 GitLab 15.0 릴리스까지 정상적으로 분석기 업데이트를 계속 받을 것이며, 그 이후에는 새로 수정된 버그 및 새로 릴리스된 기능이 분석기의 새 메이저 버전에서 사용 가능하지 않을 것입니다. 우리의 [유지보수 정책](https://docs.gitlab.com/policy/maintenance/)에 따라 버그 및 새로운 기능을 백포트하지 않기 때문입니다. 필요에 따라 보안 패치는 최신 3개의 마이너 릴리스 내에서 백포트됩니다. 특히 다음은 지원 중단 중이며 15.0 GitLab 릴리스 후에는 더 이상 업데이트되지 않습니다:

- API 보안: 버전 1
- 컨테이너 검사: 버전 4
- 범위 가이드 퍼징 테스트: 버전 2
- 종속성 검사: 버전 2
- 동적 애플리케이션 보안 테스트(DAST): 버전 2
- 코드 기반 인프라(IaC) 검사: 버전 1
- 라이선스 검사: 버전 3
- 시크릿 검색: 버전 3
- 정적 애플리케이션 보안 테스트(SAST): [모든 분석기](https://docs.gitlab.com/user/application_security/sast/#supported-languages-and-frameworks)의 버전 2, `gosec`는 현재 버전 3입니다를 제외하고
  - `bandit`: 버전 2
  - `brakeman`: 버전 2
  - `eslint`: 버전 2
  - `flawfinder`: 버전 2
  - `gosec`: 버전 3
  - `kubesec`: 버전 2
  - `mobsf`: 버전 2
  - `nodejs-scan`: 버전 2
  - `phpcs-security-audit`: 버전 2
  - `pmd-apex`: 버전 2
  - `security-code-scan`: 버전 2
  - `semgrep`: 버전 2
  - `sobelow`: 버전 2
  - `spotbugs`: 버전 2

### Sidekiq 메트릭 및 상태 확인 구성 {#sidekiq-metrics-and-health-checks-configuration}

- GitLab 14.7에서 공지
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/347509)를 참조하세요.

단일 프로세스 및 포트를 사용하여 Sidekiq 메트릭 및 상태 확인을 내보내는 것이 지원 중단됩니다. 15.0에서 지원이 제거됩니다.

우리는 Sidekiq을 업데이트하여 [두 개의 별도 프로세스에서 메트릭 및 상태 확인을 내보내](https://gitlab.com/groups/gitlab-org/-/epics/6409) 안정성과 가용성을 향상시키고 엣지 케이스에서 데이터 손실을 방지합니다. 이들은 두 개의 별도 서버이므로 15.0에서 메트릭 및 상태 확인을 위해 별도의 포트를 명시적으로 설정하기 위해 구성 변경이 필요합니다. `sidekiq['health_checks_*']`에 대해 새로 도입된 설정은 항상 `gitlab.rb`에서 설정해야 합니다. 자세한 내용은 [Sidekiq 구성](https://docs.gitlab.com/administration/sidekiq/)에 대한 설명서를 확인하세요.

이러한 변경 사항은 새 엔드포인트를 스크래이프하기 위해 Prometheus에서 또는 새 상태 확인 포트를 대상으로 하기 위해 k8s 상태 확인에서 업데이트를 요구하며, 그렇지 않으면 메트릭이나 상태 확인이 사라집니다.

지원 중단 기간 동안 이러한 설정은 선택 사항이며 GitLab은 Sidekiq 상태 확인 포트를 `sidekiq_exporter`과 동일한 포트로 기본값을 지정하고 하나의 서버만 실행합니다(현재 동작을 변경하지 않음). 둘 다 설정되고 다른 포트가 제공되는 경우에만 별도의 메트릭 서버가 Sidekiq 메트릭을 제공하기 위해 회전하여 Sidekiq이 15.0에서 동작하는 방식과 유사합니다.

### 정적 사이트 편집기 {#static-site-editor}

- GitLab 14.7에서 공지
- GitLab 15.0에서 제거
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/347137)를 참조하세요.

정적 사이트 편집기는 GitLab 15.0부터 더 이상 사용할 수 없습니다. GitLab 전체의 마크다운 편집 환경 개선으로 유사한 이점을 제공하지만 더 넓은 범위를 제공합니다. 정적 사이트 편집기에 대한 들어오는 요청은 [웹 IDE](https://docs.gitlab.com/user/project/web_ide/)로 리디렉션됩니다.

정적 사이트 편집기의 현재 사용자는 기존 프로젝트에서 구성 파일을 제거하는 방법을 포함한 자세한 내용은 [설명서](https://docs.gitlab.com/user/project/web_ide/)를 볼 수 있습니다.

### SLES 12 SP2 지원 {#support-for-sles-12-sp2}

- GitLab 14.5에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))

SUSE Linux Enterprise Server(SLES) 12 SP2의 장기 서비스 및 지원(LTSS) [2021년 3월 31일에 종료](https://www.suse.com/lifecycle/)되었습니다. SP2의 CA 인증서에는 만료된 DST 루트 인증서가 포함되어 있으며 새 CA 인증서 패키지 업데이트를 받지 않고 있습니다. 우리는 일부 [해결 방법](https://gitlab.com/gitlab-org/gitlab-omnibus-builder/-/merge_requests/191)을 구현했지만 빌드를 계속 제대로 실행할 수 없을 것입니다.

### Gitaly와 GitLab의 나머지 부분 사이에 배포된 gRPC 인식 프록시에 대한 지원 {#support-for-grpc-aware-proxy-deployed-between-gitaly-and-rest-of-gitlab}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))

권장되지 않거나 문서화되지 않았지만 Gitaly와 GitLab의 나머지 부분 사이에 gRPC 인식 프록시를 배포할 수 있었습니다. 예를 들어 NGINX 및 Envoy입니다. gRPC 인식 프록시를 배포하는 기능은 [지원 중단](https://gitlab.com/gitlab-org/gitlab/-/issues/352517)되었습니다. 현재 Gitaly 연결에 대해 gRPC 인식 프록시를 사용 중인 경우 프록시 구성을 TCP 또는 TLS 프록시(OSI 계층 4)를 사용하도록 변경해야 합니다.

Gitaly Cluster는 GitLab 13.12에서 gRPC 인식 프록시와 호환되지 않게 되었습니다. 이제 모든 GitLab 설치는 Gitaly Cluster 없이도 gRPC 인식 프록시와 호환되지 않습니다.

일부 내부 RPC 트래픽을 사용자 정의 프로토콜(gRPC 대신)을 통해 전송함으로써 처리량을 증가시키고 Go 가비지 수집 지연을 줄입니다. 자세한 내용은 [관련 에픽](https://gitlab.com/groups/gitlab-com/gl-infra/-/epics/463)을 참조하세요.

### 테스트 범위 프로젝트 CI/CD 설정 {#test-coverage-project-cicd-setting}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))

GitLab 15.0에서 테스트 범위 패턴 설정을 단순화하기 위해 [테스트 범위 구문 분석을 위한 프로젝트 설정](https://docs.gitlab.com/ci/pipelines/settings/#add-test-coverage-results-using-project-settings-removed)이 제거됩니다.

대신 프로젝트의 `.gitlab-ci.yml`을(를) 사용하여 `coverage` 키워드가 있는 정규식을 제공하여 머지 요청에서 테스팅 범위 결과를 설정합니다.

### GitLab에서 추적 {#tracing-in-gitlab}

- GitLab 14.7에서 공지
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/346540)를 참조하세요.

GitLab에서 추적하는 것은 Jaeger, 오픈 소스 엔드 투 엔드 분산 추적 시스템과의 통합입니다. GitLab 사용자는 자신의 Jaeger 인스턴스로 이동하여 배포된 애플리케이션의 성능에 대한 통찰력을 얻을 수 있으며, 요청을 처리하는 각 함수 또는 마이크로서비스를 추적할 수 있습니다. GitLab에서의 추적은 GitLab 14.7에서 지원 중단되었으며 15.0에서 제거할 예정입니다. 가능한 대체 조치에 대한 작업을 추적하려면 [GitLab과의 Opstrace 통합](https://gitlab.com/groups/gitlab-org/-/epics/6976) 이슈를 참조하세요.

### 컨테이너 레지스트리 그룹 수준 API에 대한 업데이트 {#update-to-the-container-registry-group-level-api}

- GitLab 14.5에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/336912)를 참조하세요.

마일스톤 15.0에서 `tags` 및 `tags_count` 매개변수에 대한 지원은 [그룹에서 레지스트리 리포지토리를 가져오는](https://docs.gitlab.com/api/container_registry/#within-a-group) 컨테이너 레지스트리 API에서 제거됩니다.

`GET /groups/:id/registry/repositories` 엔드포인트는 유지되지만 태그에 대한 정보를 반환하지 않습니다. 태그에 대한 정보를 얻으려면 기존 `GET /registry/repositories/:id` 엔드포인트를 사용할 수 있으며, 이는 오늘과 같이 `tags` 및 `tag_count` 옵션을 계속 지원합니다. 후자는 이미지 리포지토리당 한 번씩 호출해야 합니다.

### 가치 흐름 분석 필터링 계산 변경 {#value-stream-analytics-filtering-calculation-change}

- GitLab 14.5에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/343210)를 참조하세요.

우리는 가치 흐름 분석에서 날짜 필터가 작동하는 방식을 변경하고 있습니다. 이슈 또는 머지 요청이 생성된 시간으로 필터링하는 대신 날짜 필터는 주어진 스테이지의 종료 이벤트 시간으로 필터링됩니다. 이로 인해 이 변경 사항이 적용된 후 완전히 다른 수치가 발생합니다.

가치 흐름 분석 메트릭을 모니터링하고 날짜 필터에 의존하는 경우 데이터 손실을 방지하려면 이 변경 사항 전에 데이터를 저장해야 합니다.

### 취약성 확인 {#vulnerability-check}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))

취약성 확인 기능은 GitLab 14.8에서 지원 중단되었으며 GitLab 15.0에서 제거할 예정입니다. 대신 새로운 보안 승인 기능으로 마이그레이션할 것을 권장합니다. **보안 & 준수** > **정책**으로 이동하여 새 스캔 결과 정책을 만들어 수행할 수 있습니다.

새로운 보안 승인 기능은 취약성 확인과 유사합니다. 예를 들어 둘 다 보안 취약성을 포함하는 MR에 대한 승인을 요구할 수 있습니다. 그러나 보안 승인은 이전 경험을 여러 가지 방식으로 향상시킵니다:

- 사용자는 보안 승인 규칙을 편집할 수 있는 사람을 선택할 수 있습니다. 따라서 독립적인 보안 또는 준수 팀은 개발 프로젝트 유지 관리자가 규칙을 수정하는 것을 방지하는 방식으로 규칙을 관리할 수 있습니다.
- 여러 규칙을 만들고 연결하여 각 스캐너 유형에 대해 다양한 심각도 임계값으로 필터링할 수 있습니다.
- 보안 승인 규칙의 원하는 변경 사항에 대해 2단계 승인 프로세스를 적용할 수 있습니다.
- 단일 보안 정책 세트를 여러 개발 프로젝트에 적용하여 단일 중앙화된 규칙 세트 유지 관리를 용이하게 할 수 있습니다.

### 기본 `PackageType`의 `Versions` {#versions-on-base-packagetype}

- GitLab 14.5에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/327453)를 참조하세요.

[패키지 레지스트리 GraphQL API](https://gitlab.com/groups/gitlab-org/-/epics/6318)를 만드는 작업의 일부로 패키지 그룹은 기본 `PackageType` 유형에 대해 `Version` 유형을 지원 중단하고 [`PackageDetailsType`](https://docs.gitlab.com/api/graphql/reference/objects/#packagedetailstype)로 이동했습니다.

마일스톤 15.0에서 `Version`을(를) `PackageType`에서 완전히 제거합니다.

### `apiFuzzingCiConfigurationCreate` GraphQL 변경 {#apifuzzingciconfigurationcreate-graphql-mutation}

- GitLab 14.6에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/333233)를 참조하세요.

API 퍼징 구성 스니펫은 이제 클라이언트 측에서 생성되며 더 이상 API 요청이 필요하지 않습니다. 따라서 더 이상 GitLab에서 사용되지 않는 `apiFuzzingCiConfigurationCreate` 변수를 지원 중단하고 있습니다.

### `artifacts:reports:cobertura` 키워드 {#artifactsreportscobertura-keyword}

- GitLab 14.7에서 공지
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/348980)를 참조하세요.

현재 GitLab의 테스트 범위 시각화는 Cobertura 보고서만 지원합니다. 15.0부터 `artifacts:reports:cobertura` 키워드는 [`artifacts:reports:coverage_report`](https://gitlab.com/gitlab-org/gitlab/-/issues/344533)로 대체됩니다. Cobertura는 15.0에서 유일하게 지원되는 보고서 파일이지만 이것이 GitLab이 다른 보고서 유형을 지원하는 첫 번째 단계입니다.

### `defaultMergeCommitMessageWithDescription` GraphQL API 필드 {#defaultmergecommitmessagewithdescription-graphql-api-field}

- GitLab 14.5에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/345451)를 참조하세요.

GraphQL API 필드 `defaultMergeCommitMessageWithDescription`은(는) 지원 중단되었으며 GitLab 15.0에서 제거될 것입니다. 커밋 메시지 템플릿이 설정된 프로젝트의 경우 템플릿을 무시합니다.

### `dependency_proxy_for_private_groups` 기능 플래그 {#dependency_proxy_for_private_groups-feature-flag}

- GitLab 14.5에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/276777)를 참조하세요.

우리는 [GitLab-#11582](https://gitlab.com/gitlab-org/gitlab/-/issues/11582)가 공개 그룹이 종속성 프록시를 사용하는 방식을 변경했기 때문에 기능 플래그를 추가했습니다. 이 변경 이전에는 인증 없이 종속성 프록시를 사용할 수 있었습니다. 변경하려면 종속성 프록시를 사용하려면 인증이 필요합니다.

마일스톤 15.0에서 기능 플래그를 완전히 제거합니다. 앞으로 종속성 프록시를 사용할 때 인증해야 합니다.

### 컨테이너 레지스트리용 `htpasswd` 인증 {#htpasswd-authentication-for-the-container-registry}

- GitLab 14.9에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))

컨테이너 레지스트리는 [인증](https://gitlab.com/gitlab-org/container-registry/-/blob/master/docs/configuration.md#auth)을 `htpasswd`으로 지원합니다. [Apache `htpasswd` 파일](https://httpd.apache.org/docs/2.4/programs/htpasswd.html)에 의존하며, 암호는 `bcrypt`을 사용하여 해시됩니다.

GitLab(제품)의 맥락에서 사용되지 않기 때문에 `htpasswd` 인증은 GitLab 14.9에서 지원 중단되고 GitLab 15.0에서 제거됩니다.

### `pipelines` 필드 자체의 `version` 필드 {#pipelines-field-from-the-version-field}

- GitLab 14.5에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/342882)를 참조하세요.

GraphQL에는 [`PackageDetailsType`](https://docs.gitlab.com/api/graphql/reference/objects/#packagedetailstype)에서 패키지 버전용 파이프라인을 얻기 위해 사용할 수 있는 두 개의 `pipelines` 필드가 있습니다:

- `versions` 필드의 `pipelines` 필드. 이는 패키지의 모든 버전과 관련된 모든 파이프라인을 반환하며, 이는 메모리에 많은 수의 객체를 끌어올릴 수 있고 성능 문제를 초래할 수 있습니다.
- 특정 `version`의 `pipelines` 필드입니다. 이는 해당 단일 패키지 버전과 관련된 파이프라인만 반환합니다.

가능한 성능 문제를 완화하기 위해 마일스톤 15.0에서 `versions` 필드의 `pipelines` 필드를 제거합니다. 패키지의 모든 버전에 대한 모든 파이프라인을 더 이상 얻을 수 없지만 해당 버전의 남은 `pipelines` 필드를 통해 단일 버전의 파이프라인을 여전히 얻을 수 있습니다.

### `projectFingerprint` 자체의 `PipelineSecurityReportFinding` GraphQL {#projectfingerprint-in-pipelinesecurityreportfinding-graphql}

- GitLab 14.8에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))

`projectFingerprint` 필드는 [`PipelineSecurityReportFinding`](https://docs.gitlab.com/api/graphql/reference/objects/#pipelinesecurityreportfinding) GraphQL 객체에서 지원 중단되고 있습니다. 이 필드에는 보안 결과의 고유성을 결정하는 데 사용되는 "지문"이 포함되어 있습니다. 지문 계산 방법이 변경되어 다른 값이 발생합니다. 앞으로 새 값은 UUID 필드에 노출됩니다. 이전에 `projectFingerprint` 필드에서 사용 가능한 데이터는 결국 완전히 제거될 것입니다.

### `promote-db` 명령`gitlab-ctl` {#promote-db-command-from-gitlab-ctl}

- GitLab 14.5에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/345207)를 참조하세요.

GitLab 14.5에서 우리는 장애 조치 중에 모든 Geo 보조 노드를 1차로 승격하는 명령 `gitlab-ctl promote`을(를) 도입했습니다. 이 명령은 다중 노드 Geo 보조 사이트에서 데이터베이스 노드를 승격하는 데 사용되는 `gitlab-ctl promote-db`을(를) 대체합니다. `gitlab-ctl promote-db`은(는) 계속 기능하며 GitLab 15.0까지 사용할 수 있습니다. Geo 고객이 스테이징 환경에서 새 `gitlab-ctl promote` 명령을 테스트하고 장애 조치 절차에 새 명령을 통합하기 시작할 것을 권장합니다.

### `promote-to-primary-node` 명령`gitlab-ctl` {#promote-to-primary-node-command-from-gitlab-ctl}

- GitLab 14.5에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/345207)를 참조하세요.

GitLab 14.5에서 우리는 장애 조치 중에 모든 Geo 보조 노드를 1차로 승격하는 명령 `gitlab-ctl promote`을(를) 도입했습니다. 이 명령은 단일 노드 Geo 사이트에만 사용 가능했던 `gitlab-ctl promote-to-primary-node`을(를) 대체합니다. `gitlab-ctl promote-to-primary-node`은(는) 계속 기능하며 GitLab 15.0까지 사용할 수 있습니다. Geo 고객이 스테이징 환경에서 새 `gitlab-ctl promote` 명령을 테스트하고 장애 조치 절차에 새 명령을 통합하기 시작할 것을 권장합니다.

### CI/CD 구성의 `type` 및 `types` 키워드 {#type-and-types-keyword-in-cicd-configuration}

- GitLab 14.6에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))

`type` 및 `types` CI/CD 키워드는 GitLab 15.0에서 제거됩니다. 이러한 키워드를 사용하는 파이프라인은 작동을 중지하므로 동일한 동작을 하는 `stage` 및 `stages`로 전환해야 합니다.

### bundler-audit 종속성 검사 도구 {#bundler-audit-dependency-scanning-tool}

- GitLab 14.6에서 발표됨
- GitLab 15.0에서 제거 ([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/289832)를 참조하세요.

14.6부터 bundler-audit는 종속성 검사에서 지원 중단되고 있습니다. 지원 중단되는 동안 CI/CD 템플릿에 계속 포함될 것입니다. 2022년 5월 22일 15.0에서 종속성 검사에서 bundler-audit을 제거합니다. 이 제거 후 Ruby 검사 기능은 영향을 받지 않을 것입니다. Gemnasium에서 여전히 다루고 있기 때문입니다.

DS_EXCLUDED_ANALYZERS를 사용하여 bundler-audit을 명시적으로 제외한 경우 15.0에서 정리(참조 제거)해야 합니다. 파이프라인의 종속성 검사 구성을 사용자 정의한 경우(예: `bundler-audit-dependency_scanning` 작업을 편집하려면) 15.0의 제거 전에 gemnasium-dependency_scanning으로 전환하여 파이프라인이 실패하지 않도록 하려고 할 것입니다. DS_EXCLUDED_ANALYZERS를 사용하여 bundler-audit을 참조하지 않았거나 bundler-audit을 위해 특별히 템플릿을 사용자 정의하지 않은 경우 조치를 취할 필요가 없습니다.

## GitLab 14.10 {#gitlab-1410}

### Composer 종속성 다운로드 권한 변경 {#permissions-change-for-downloading-composer-dependencies}

- GitLab 14.9에서 발표됨
- GitLab 14.10에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))

GitLab Composer 리포지토리는 PHP 종속성을 푸시하고, 검색하고, 메타데이터를 가져오고, 다운로드하는 데 사용할 수 있습니다. 종속성 다운로드를 제외한 모든 이러한 작업에는 인증이 필요합니다.

인증 없이 Composer 종속성을 다운로드하는 것은 GitLab 14.9에서 지원 중단되었으며 GitLab 15.0에서 제거될 것입니다. GitLab 15.0부터 Composer 종속성을 다운로드하려면 인증해야 합니다.

## GitLab 14.9 {#gitlab-149}

### 구성 가능한 Gitaly `per_repository` 선택 전략 {#configurable-gitaly-per_repository-election-strategy}

- GitLab 14.8에서 발표됨
- GitLab 14.9에서 제거됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/352612)를 참조하세요.

`per_repository` Gitaly 선택 전략을 구성하는 것은 [지원 중단](https://gitlab.com/gitlab-org/gitlab/-/issues/352612)되었습니다. GitLab 14.0 이후로 `per_repository`이(가) 유일한 옵션이었습니다.

이 변경 사항은 코드베이스를 깨끗하게 유지하기 위한 정기적인 유지보수의 일부입니다.

### 통합 오류 추적이 기본적으로 비활성화됨 {#integrated-error-tracking-disabled-by-default}

- GitLab 14.9에서 발표됨
- GitLab 14.9에서 제거됨([주요 변경 사항](https://docs.gitlab.com/update/terminology/#breaking-change))
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/353639)를 참조하세요.

GitLab 14.4에서 GitLab은 Sentry를 대체하는 통합 오류 추적 백엔드를 출시했습니다. 이 기능으로 인해 데이터베이스 성능 문제가 발생했습니다. GitLab 14.9에서 통합 오류 추적은 GitLab.com에서 제거되고 GitLab Self-Managed에서 기본적으로 꺼집니다. 이 기능의 향후 개발을 탐색하는 동안 프로젝트 설정에서 [오류 추적을 Sentry로 변경](https://docs.gitlab.com/operations/error_tracking/#sentry-error-tracking)하여 Sentry 백엔드로 전환할 것을 고려하세요.

이 제거의 추가 배경은 [통합 오류 추적 비활성화](https://gitlab.com/groups/gitlab-org/-/epics/7580)를 참조하세요. 피드백이 있으면 [피드백:에 댓글을 추가하세요: 통합 오류 추적 제거](https://gitlab.com/gitlab-org/gitlab/-/issues/355493).

## GitLab 14.8 {#gitlab-148}

### openSUSE Leap 15.2 패키지 {#opensuse-leap-152-packages}

- GitLab 14.5에서 발표됨
- GitLab 14.8에서 제거됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/6427)를 참조하세요.

openSUSE Leap 15.2에 대한 배포 지원 및 보안 업데이트는 [2021년 12월에 종료](https://en.opensuse.org/Lifetime#openSUSE_Leap)되고 있습니다.

14.5부터 openSUSE Leap 15.3용 패키지를 제공하고 있으며 14.8 마일스톤에서 openSUSE Leap 15.2용 패키지 제공을 중단합니다.

## GitLab 14.6 {#gitlab-146}

### 일반 패키지로 배포된 릴리스 CLI {#release-cli-distributed-as-a-generic-package}

- GitLab 14.2에서 발표됨
- GitLab 14.6에서 제거됨

[release-cli](https://gitlab.com/gitlab-org/release-cli)는 GitLab 14.2부터 [일반 패키지](https://gitlab.com/gitlab-org/release-cli/-/packages)로 릴리스됩니다. GitLab 14.5까지 계속해서 이를 S3에 바이너리로 배포할 것이며 GitLab 14.6에서 S3 배포를 중단합니다.

## GitLab 14.5 {#gitlab-145}

### 작업 실행기 Pod를 도구 상자로 이름 바꾸기 {#rename-task-runner-pod-to-toolbox}

- GitLab 14.2에서 발표됨
- GitLab 14.5에서 제거됨

작업 실행기 Pod는 GitLab 애플리케이션 내에서 정기적인 정리 작업을 실행하는 데 사용되며 종종 GitLab Runner와 혼동됩니다. 따라서 [작업 실행기가 도구 상자로 이름이 바뀔 것입니다](https://gitlab.com/groups/gitlab-org/charts/-/epics/25).

이로 인해 하위 차트가 이름 바뀝니다: `gitlab/task-runner`에서 `gitlab/toolbox`로. 결과 Pod는 `{{ .Release.Name }}-toolbox` 라인을 따라 이름이 지정되며, 종종 `gitlab-toolbox`입니다. 레이블 `app=toolbox`로 찾을 수 있습니다.

## 보류 중인 변경 사항 {#pending-changes}

다음 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

### CodeClimate 기반 코드 품질 검사가 제거됩니다 {#codeclimate-based-code-quality-scanning-will-be-removed}

- GitLab 17.3에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/471677)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

향후 릴리스에서 CodeClimate 기반 코드 품질 검사를 제거할 것입니다. 이 변경 사항은 이전에 GitLab 18.0 예정이었으며 현재 연기되었습니다.

대신 CI/CD 파이프라인에서 직접 품질 도구를 사용하고 [도구의 보고서를 아티팩트로 제공](https://docs.gitlab.com/ci/testing/code_quality/#import-code-quality-results-from-a-cicd-job)하세요. 우리는 이미 많은 도구를 통합하는 방법을 문서화했으며 [설명서](https://docs.gitlab.com/ci/testing/code_quality/#integrate-common-tools-with-code-quality)를 따라 통합할 수 있습니다.

우리는 이 변경을 다음에 의해 구현할 것으로 예상합니다:

1. [`Code-Quality.gitlab-ci.yml` CI/CD 템플릿](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/Code-Quality.gitlab-ci.yml)을 변경하여 더 이상 검사를 실행하지 않습니다. 현재 이 템플릿은 CodeClimate 기반 검사를 실행합니다. (제거 후에도 템플릿을 `include`하는 파이프라인에 미치는 영향을 줄이기 위해 템플릿을 삭제하지 않고 변경할 계획입니다.)
1. Auto DevOps의 일부로 CodeClimate 기반 검사를 더 이상 실행하지 않습니다.

즉시, CodeClimate 기반 검사는 [제한된 업데이트](https://docs.gitlab.com/update/terminology/#deprecation)만 받을 것입니다. 지원 종료 후 추가 업데이트를 제공하지 않을 것입니다. 그러나 이전에 게시된 컨테이너 이미지를 삭제하거나 사용자 정의 CI/CD 파이프라인 작업 정의를 사용하여 실행하는 기능을 제거하지 않을 것입니다.

자세한 내용은 [품질 위반에 대한 코드 검사](https://docs.gitlab.com/ci/testing/code_quality/#scan-code-for-quality-violations)를 참조하세요.

### 컨테이너 레지스트리 레거시 메타데이터 저장소 {#container-registry-legacy-metadata-storage}

- GitLab 18.5에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/571531)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

GitLab 컨테이너 레지스트리의 레거시 메타데이터 저장소 접근 방식은 컨테이너 레지스트리 메타데이터 데이터베이스를 선호하여 지원 중단됩니다.

GitLab.com은 이미 메타데이터 데이터베이스를 사용합니다. 이 지원 중단은 현재 저장소 백엔드(객체 저장소 또는 로컬 파일 시스템)에 메타데이터 정보를 직접 저장하는 레거시 컨테이너 레지스트리를 사용하는 GitLab Self-Managed 인스턴스에 영향을 미칩니다.

레거시 메타데이터 저장소 방법은 유지 관리 모드에서 계속 지원되지만 새로운 기능이나 개선 사항을 받지 않습니다. 가능한 한 빨리 컨테이너 레지스트리 메타데이터 데이터베이스로 마이그레이션할 것을 강력히 권장합니다.

이 변경 사항은 컨테이너 레지스트리가 이미지 및 태그에 대한 메타데이터를 저장하는 방식에만 영향을 미칩니다. 저장소 백엔드 선택(객체 저장소 또는 파일 시스템)은 동일하게 유지됩니다. 메타데이터 데이터베이스에서 [객체 저장소](https://docs.gitlab.com/administration/packages/container_registry/#use-object-storage) 또는 파일 시스템 저장소를 계속 사용할 수 있습니다.

레거시 메타데이터 저장소에서 메타데이터 데이터베이스로 마이그레이션하려면 [컨테이너 레지스트리 메타데이터 데이터베이스 마이그레이션 가이드](https://docs.gitlab.com/administration/packages/container_registry_metadata_database/)를 따르세요. 마이그레이션 프로세스에는 메타데이터 데이터베이스 기능을 활성화하고 가져오기 도구를 실행하여 기존 레지스트리 데이터를 전송하는 작업이 포함됩니다.

메타데이터 데이터베이스는 더 나은 성능, 안정성을 제공하며 레거시 메타데이터 저장소 접근 방식에서 사용할 수 없는 새 컨테이너 레지스트리 기능을 활성화합니다.

### 범위 가이드 퍼징 테스트가 지원 중단됨 {#coverage-guided-fuzz-testing-is-deprecated}

- GitLab 18.0에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/517841)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

범위 가이드 퍼징 테스트는 지원 중단되었으며 GitLab 18.0부터 지원되지 않을 것입니다. 이 기능은 GitLab 19.0에서 완전히 제거될 것입니다.

범위 가이드 퍼징 테스트는 여러 오픈 소스 퍼저를 GitLab에 통합했습니다. 영향을 받는 경우 오픈 소스 퍼저를 독립 실행형 애플리케이션으로 통합하거나 [GitLab Advanced SAST](https://docs.gitlab.com/user/application_security/sast/gitlab_advanced_sast/)와 같은 다른 보안 기능으로 마이그레이션할 수 있습니다.

### JavaScript 공급 라이브러리에 대한 종속성 검사 {#dependency-scanning-for-javascript-vendored-libraries}

- GitLab 17.9에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/501308)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

[JavaScript 공급 라이브러리에 대한 종속성 검사](https://docs.gitlab.com/user/application_security/dependency_scanning/#javascript) 기능은 종속성 검사용 Gemnasium 분석기에서 제공하며 GitLab 17.9에서 지원 중단됩니다.

이 기능은 Gemnasium 분석기를 사용할 때 계속 작동하지만 새 종속성 검사 분석기로 마이그레이션한 후에는 사용할 수 없습니다. [마이그레이션 가이드](https://docs.gitlab.com/user/application_security/dependency_scanning/migration_guide_to_sbom_based_scans/)에서 자세한 내용을 확인하세요

대체 기능은 [공급 라이브러리의 종속성 검사](https://gitlab.com/groups/gitlab-org/-/epics/7186)로 개발되지만 전달 일정이 정해지지 않았습니다.

### GitLab SBOM 취약성 스캐너로 종속성 검사 업그레이드 {#dependency-scanning-upgrades-to-the-gitlab-sbom-vulnerability-scanner}

- GitLab 17.9에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/501308)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

종속성 검사 기능은 GitLab SBOM 취약성 스캐너로 업그레이드 중입니다. 이 변경의 일부로 이전에 사용된 Gemnasium 분석기(CI/CD 파이프라인에서 사용)는 GitLab 17.9에서 지원 중단됩니다.

이는 [SBOM을 사용하는 종속성 검사](https://docs.gitlab.com/user/application_security/dependency_scanning/dependency_scanning_sbom/) 기능 및 [새 종속성 검사 분석기](https://gitlab.com/gitlab-org/security-products/analyzers/dependency-scanning)로 대체되며, 이는 종속성 및 관계(종속성 그래프)를 감지하고 이미 [지속적 취약성 검사](https://docs.gitlab.com/user/application_security/continuous_vulnerability_scanning/)에서 사용하는 GitLab의 기본 제공 SBOM 취약성 스캐너에 의존합니다. 취약성을 식별합니다.

GitLab 18.5부터 이 새 기능은 제한적 출시 상태입니다. 대다수의 사용자가 새 종속성 검사 기능으로 마이그레이션할 때까지 GitLab은 Gemnasium 분석기를 계속 지원합니다. 그 다음에만 Gemnasium 분석기가 [지원 종료](https://docs.gitlab.com/update/terminology/#end-of-support)에 도달합니다.

이 업그레이드가 도입하는 상당한 변경 사항과 기능 제거로 인해 자동으로 구현되지 않을 것입니다. Gemnasium 분석기를 사용하는 기존 CI/CD 작업은 CI/CD 구성의 중단을 방지하기 위해 기본적으로 계속 기능합니다.

아래의 완전히 상세한 변경 사항을 검토하고 [마이그레이션 가이드](https://docs.gitlab.com/user/application_security/dependency_scanning/migration_guide_to_sbom_based_scans/)를 참조하여 전환을 지원하세요.

- 애플리케이션이 안정적인 종속성 검사 CI/CD 템플릿(`Dependency-Scanning.gitlab-ci.yml`)을 사용할 때 CI/CD 구성의 중단을 방지하기 위해 종속성 검사는 Gemnasium 분석기 기반의 기존 CI/CD 작업만 사용합니다.
- 애플리케이션이 최신 종속성 검사 CI/CD 템플릿(`Dependency-Scanning.latest.gitlab-ci.yml`)을 사용할 때 종속성 검사는 Gemnasium 분석기 기반의 기존 CI/CD 작업과 새 종속성 검사 분석기도 지원되는 파일 유형에서 실행됩니다. 모든 프로젝트에 대해 새 종속성 검사 분석기를 적용하도록 옵트인할 수도 있습니다.
- 기능이 성숙해짐에 따라 다른 마이그레이션 경로를 고려할 수 있습니다.
- [Gemnasium 분석기](https://gitlab.com/gitlab-org/security-products/analyzers/gemnasium/) 프로젝트가 지원 중단되었으며, 해당 컨테이너 이미지(모든 태그 및 변형)도 지원 중단됩니다: `gemnasium`, `gemnasium-maven`, `gemnasium-python`. 이러한 이미지는 GitLab 컨테이너 레지스트리에서 제거되지 않습니다.
- Gemnasium 분석기와 연결된 다음 CI/CD 변수는 지원 중단됩니다. 이러한 변수는 Gemnasium 분석기를 사용할 때 계속 작동하지만 새 종속성 검사 분석기로 마이그레이션한 후에는 효과가 없을 것입니다. 변수가 다른 컨텍스트에서도 사용되는 경우 지원 중단은 종속성 검사 기능(예: `GOOS` 및 `GOARCH` 종속성 검사 기능에 특정하지 않음)에만 적용됩니다. `DS_EXCLUDED_ANALYZERS`, `DS_GRADLE_RESOLUTION_POLICY`, `DS_IMAGE_SUFFIX`, `DS_JAVA_VERSION`, `DS_PIP_DEPENDENCY_PATH`, `DS_PIP_VERSION`, `DS_REMEDIATE_TIMEOUT`, `DS_REMEDIATE`, `GEMNASIUM_DB_LOCAL_PATH`, `GEMNASIUM_DB_REF_NAME`, `GEMNASIUM_DB_REMOTE_URL`, `GEMNASIUM_DB_UPDATE_DISABLED`, `GEMNASIUM_LIBRARY_SCAN_ENABLED`, `GOARCH`, `GOFLAGS`, `GOOS`, `GOPRIVATE`, `GRADLE_CLI_OPTS`, `GRADLE_PLUGIN_INIT_PATH`, `MAVEN_CLI_OPTS`, `PIP_EXTRA_INDEX_URL`, `PIP_INDEX_URL`, `PIPENV_PYPI_MIRROR`, `SBT_CLI_OPTS`.
- 다음 [CI/CD 구성 요소](https://gitlab.com/components/dependency-scanning/#components)는 지원 중단됩니다: Android, Rust, Swift, CocoaPods. 이들은 모든 지원되는 언어 및 패키지 관리자를 포함하는 [기본 종속성 검사 CI/CD 구성 요소](https://gitlab.com/components/dependency-scanning/-/tree/main/templates/main?ref_type=heads)로 대체됩니다.
- [취약성 해결](https://docs.gitlab.com/user/application_security/vulnerabilities/#resolve-a-vulnerability) 기능 **Yarn 프로젝트용**은 GitLab 17.9에서 지원 중단됩니다. 이 기능은 Gemnasium 분석기를 사용할 때 계속 작동하지만 새 종속성 검사 분석기로 마이그레이션한 후에는 사용할 수 없습니다. 자세한 내용은 해당 [지원 중단 공지](https://docs.gitlab.com/update/deprecations/#resolve-a-vulnerability-for-dependency-scanning-on-yarn-projects)를 참조하세요.
- [JavaScript 공급 라이브러리에 대한 종속성 검사](https://docs.gitlab.com/user/application_security/dependency_scanning/#javascript) 기능은 GitLab 17.9에서 지원 중단됩니다. 이 기능은 Gemnasium 분석기를 사용할 때 계속 작동하지만 새 종속성 검사 분석기로 마이그레이션한 후에는 사용할 수 없습니다. 자세한 내용은 해당 [지원 중단 공지](https://docs.gitlab.com/update/deprecations/#dependency-scanning-for-javascript-vendored-libraries)를 참조하세요.

### GitLab Advanced SAST가 기본적으로 활성화됨 {#gitlab-advanced-sast-will-be-enabled-by-default}

- GitLab 17.9에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/513685)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

GitLab 19.0에서 우리는 [SAST CI/CD 템플릿](https://docs.gitlab.com/user/application_security/sast#stable-vs-latest-sast-templates)을 업데이트하여 GitLab Ultimate가 있는 프로젝트에서 [GitLab Advanced SAST](https://docs.gitlab.com/user/application_security/sast/gitlab_advanced_sast/)를 기본적으로 활성화합니다. 이 변경 이전에 GitLab Advanced SAST 분석기는 CI/CD 변수 `GITLAB_ADVANCED_SAST_ENABLED`을(를) `true`로 설정하는 경우에만 활성화됩니다. 이 변경 사항은 이전에 GitLab 18.0 예정이었으며 현재 연기되었습니다.

Advanced SAST는 교차 파일, 교차 함수 검사 및 새로운 규칙 집합을 사용하여 더 정확한 결과를 제공합니다. Advanced SAST는 [지원되는 언어](https://docs.gitlab.com/user/application_security/sast/gitlab_advanced_sast/#supported-languages)에 대한 범위를 인수하고 이전 스캐너에서 해당 언어의 검사를 비활성화합니다. 자동화된 프로세스는 각 프로젝트의 기본 브랜치에서 첫 번째 검사 후 결과를 마이그레이션합니다(여전히 감지된 경우).

프로젝트를 더 자세히 검사하기 때문에 Advanced SAST는 프로젝트를 검사하는 데 더 많은 시간이 걸릴 수 있습니다. 필요한 경우 [GitLab Advanced SAST를 비활성화](https://docs.gitlab.com/user/application_security/sast/gitlab_advanced_sast/#disable-gitlab-advanced-sast-scanning)할 수 있습니다. CI/CD 변수 `GITLAB_ADVANCED_SAST_ENABLED`을(를) `false`으로 설정합니다. 이 변수를 프로젝트, 그룹 또는 정책에서 지금 설정하여 GitLab 19.0에서 Advanced SAST가 기본적으로 활성화되는 것을 방지할 수 있습니다.

### GitLab Runner Docker Machine 실행기가 지원 중단됨 {#gitlab-runner-docker-machine-executor-is-deprecated}

- GitLab 17.5에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/498268)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

[GitLab Runner Docker Machine 실행기](https://docs.gitlab.com/runner/executors/docker_machine/)가 지원 중단되었으며 GitLab 20.0(2027년 5월)에서 지원되는 기능으로 완전히 제거될 것입니다. Docker Machine 대체 [GitLab Runner 자동 스케일러](https://docs.gitlab.com/runner/runner_autoscale/)는 Amazon Web Services(AWS) EC2, Google Compute Engine(GCE) 및 Microsoft Azure 가상 머신(VM)용 GitLab 개발 플러그인과 함께 일반적으로 사용 가능합니다. 이 공지로 GitL

### GraphQL API의 GitLab Runner 플랫폼 및 설정 지침 {#gitlab-runner-platforms-and-setup-instructions-in-graphql-api}

- GitLab 15.9에서 발표
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/387937)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

GitLab Runner 플랫폼 및 설치 지침을 가져오는 `runnerPlatforms` 및 `runnerSetup` 쿼리는 더 이상 사용 중단되며 GraphQL API에서 제거됩니다. 설치 지침은 이러한 API 쿼리를 사용하는 대신 [GitLab Runner 설명서](https://docs.gitlab.com/runner/)를 참조하세요.

### GitLab Self-Managed의 Kubernetes와 인증서 기반 통합 {#gitlab-self-managed-certificate-based-integration-with-kubernetes}

- GitLab 14.5에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/groups/gitlab-org/configure/-/epics/8)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

Kubernetes와의 인증서 기반 통합은 [더 이상 사용 중단되고 제거됩니다](https://about.gitlab.com/blog/deprecating-the-cert-based-kubernetes-integration/).

GitLab Self-Managed의 경우 GitLab 15.0에서 [기능 플래그](https://docs.gitlab.com/administration/feature_flags/#enable-or-disable-the-feature) `certificate_based_clusters`를 도입하므로 인증서 기반 통합을 계속 활성화할 수 있습니다. 그러나 기능 플래그는 기본적으로 비활성화되므로 이 변경 사항은 **주요 변경 사항**입니다.

Kubernetes와의 더욱 강력하고 안전하며 향후 추가될 신뢰할 수 있는 통합을 위해 [Kubernetes 에이전트](https://docs.gitlab.com/user/clusters/agent/)를 사용하여 Kubernetes 클러스터를 GitLab과 연결하세요. 이 마이그레이션에 대한 정보는 [Kubernetes용 에이전트로 마이그레이션](https://docs.gitlab.com/user/infrastructure/clusters/migrate_to_gitlab_agent/)을(를) 참조하세요.

새로운 솔루션이 기능 패리티를 달성할 때까지 GitLab은 이 기능을 제거하지 않습니다. 제거 차단 요소에 대한 자세한 내용은 [이슈 199](https://gitlab.com/gitlab-org/configure/general/-/issues/199)를 참조하세요.

이 지원 중단에 대한 업데이트 및 세부 정보는 [에픽 8](https://gitlab.com/groups/gitlab-org/configure/-/epics/8)을(를) 참조하세요.

### GitLab.com 인증서 기반 Kubernetes 통합 {#gitlabcom-certificate-based-integration-with-kubernetes}

- GitLab 14.5에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/groups/gitlab-org/configure/-/epics/8)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

인증서 기반 Kubernetes 통합은 [지원이 중단되고 제거됩니다](https://about.gitlab.com/blog/deprecating-the-cert-based-kubernetes-integration/). GitLab.com 사용자로서 새로운 네임스페이스에서는 GitLab 15.0부터 인증서 기반 접근 방식을 사용하여 GitLab과 클러스터를 통합할 수 없습니다. 현재 사용자의 통합은 네임스페이스별로 활성화됩니다.

더 강력하고 안전하며 향후 지원될 예정인 안정적인 Kubernetes 통합을 위해 [Kubernetes용 에이전트](https://docs.gitlab.com/user/clusters/agent/)를 사용하여 Kubernetes 클러스터를 GitLab과 연결하는 것이 좋습니다. [마이그레이션하려면 어떻게 하나요?](https://docs.gitlab.com/user/infrastructure/clusters/migrate_to_gitlab_agent/)

이 지원 중단에 대한 업데이트 및 세부 정보는 [이 에픽](https://gitlab.com/groups/gitlab-org/configure/-/epics/8)을(를) 따르세요.

GitLab Self-Managed 고객은 여전히 [기능 플래그와 함께](https://docs.gitlab.com/update/deprecations/#self-managed-certificate-based-integration-with-kubernetes) 이 기능을 사용할 수 있습니다.

### `dependencyProxyTotalSizeInBytes` 필드의 GraphQL 지원 중단 {#graphql-deprecation-of-dependencyproxytotalsizeinbytes-field}

- GitLab 16.1에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/414236)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

GraphQL을 사용하여 GitLab 종속성 프록시가 사용하는 스토리지 양을 쿼리할 수 있습니다. 그러나 `dependencyProxyTotalSizeInBytes` 필드는 약 2기가바이트로 제한되어 있으며, 이는 종속성 프록시에 항상 충분하지 않습니다. 결과적으로 `dependencyProxyTotalSizeInBytes`은(는) 지원이 중단되었습니다.

GitLab 16.1에서 도입된 `dependencyProxyTotalSizeBytes`을(를) 대신 사용하세요.

### OWASP 상위 10 2017별 그룹 취약성 보고서는 지원이 중단됨 {#group-vulnerability-report-by-owasp-top-10-2017-is-deprecated}

- GitLab 17.0에서 발표
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/458835)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

OWASP 상위 10 2017별 취약성 보고서 그룹화는 지원이 중단되었으며 OWASP 상위 10 2021별 그룹화로 대체되었습니다. 향후 취약성 보고서의 그룹화를 위해 OWASP 상위 10의 가장 최신 버전을 지원할 예정입니다. 이 변경 사항과 함께 이 기능이 사용하는 2017 GraphQL API 열거형도 지원이 중단되고 제거됩니다. 추가 세부 정보는 [이 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/488433)에 포함되어 있습니다.

### 파이프라인 변수 사용의 보안 강화 {#increased-default-security-for-use-of-pipeline-variables}

- GitLab 17.7에서 발표
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/502382)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

GitLab은 안전-기본값-우선 관행을 믿습니다. 이를 위해 CI/CD 변수 사용과 관련된 최소 권한 원칙을 지원하기 위해 일부 변경 사항을 적용하고 있습니다. 현재 개발자 역할 이상의 사용자는 확인이나 옵트인 없이 기본적으로 [파이프라인 변수](https://docs.gitlab.com/ci/variables/#use-pipeline-variables)를 사용할 수 있습니다.

최소 역할을 권장되는 [소유자만 또는 아무도 없음](https://docs.gitlab.com/ci/variables/#restrict-pipeline-variables)으로 높여 파이프라인 변수에 대한 더 안전-기본값-우선 환경을 이미 사용할 수 있습니다. 17.7부터 GitLab.com의 새 네임스페이스에 있는 모든 새 프로젝트의 기본값은 `no one allowed`입니다.

### OpenTofu CI/CD 템플릿 {#opentofu-cicd-template}

- GitLab 17.1에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/components/opentofu/-/issues/43#note_1913822299)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

16.8에서 OpenTofu CI/CD 템플릿을 도입했으며, 당시에는 GitLab Self-Managed에서 CI/CD 구성 요소를 아직 사용할 수 없었습니다. [GitLab Self-Managed용 GitLab CI/CD 구성 요소](https://docs.gitlab.com/ci/components/#use-a-gitlabcom-component-in-a-self-managed-instance)의 도입으로 중복되는 OpenTofu CI/CD 템플릿을 제거하고 CI/CD 구성 요소를 대신 사용합니다.

CI/CD 템플릿에서 구성 요소로 마이그레이션하는 방법에 대한 정보는 [OpenTofu 구성 요소 문서](https://gitlab.com/components/opentofu#usage-on-self-managed)를 참조하세요.

### 파이프라인 실행 정책 `inject_ci` 전략이 `inject_policy`로 대체됨 {#pipeline-execution-policies-inject_ci-strategy-replaced-by-inject_policy}

- GitLab 17.11에서 발표
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/573447)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

파이프라인 실행 정책에서 [사용자 정의 스테이지](https://gitlab.com/gitlab-org/gitlab/-/issues/475152)의 도입(GitLab 17.9에서 사용 가능)으로 인해 `inject_policy` 구성 옵션을 도입하여 지원이 중단된 `inject_ci`을(를) 대체합니다.

이 새로운 전략은 `inject_ci` 전략을 사용하는 기존 파이프라인 실행 정책을 가진 사용자를 위해 사용자 정의 스테이지 기능의 순조로운 출시를 가능하게 합니다.

제거 예정에 대비하려면 `inject_ci`을(를) 사용하는 모든 파이프라인 실행 정책을 `inject_policy`을(를) 사용하도록 업데이트하세요.

### 일반적인 사용자, 프로젝트 및 그룹 API 엔드포인트에 대한 속도 제한 {#rate-limits-for-common-user-project-and-group-api-endpoints}

- GitLab 17.4에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/480914)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

속도 제한은 일반적으로 사용되는 [사용자](https://docs.gitlab.com/administration/settings/user_and_ip_rate_limits/), [프로젝트](https://docs.gitlab.com/administration/settings/rate_limit_on_projects_api/), 및 [그룹](https://docs.gitlab.com/administration/settings/rate_limit_on_groups_api/) 엔드포인트에 기본적으로 활성화됩니다. 이러한 속도 제한을 기본적으로 활성화하면 과도한 API 사용이 더 넓은 사용자 경험에 부정적인 영향을 미칠 가능성을 줄여 전체 시스템 안정성을 개선할 수 있습니다. 속도 제한을 초과하는 요청은 [HTTP 429](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/429) 오류 코드 및 [추가 속도 제한 헤더](https://docs.gitlab.com/administration/settings/user_and_ip_rate_limits/#response-headers)를 반환합니다.

기본 속도 제한은 대부분의 사용 현황을 방해하지 않도록 의도적으로 상당히 높게 설정되었으며, GitLab.com에서 볼 수 있는 요청 속도를 기반으로 합니다. 인스턴스 관리자는 이미 존재하는 기타 속도 제한과 유사하게 필요에 따라 관리 영역에서 더 높거나 낮은 제한을 설정할 수 있습니다.

### GraphQL API에서 `ContainerRepository` 필드의 `migrationState` 제거 {#removal-of-migrationstate-field-in-containerrepository-graphql-api}

- GitLab 17.6에서 발표
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/459869)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

GitLab GraphQL API의 `ContainerRepositoryType` 중 `migrationState` 필드는 지원이 중단되었습니다. 이 지원 중단은 API를 간소화하고 개선하려는 노력의 일부입니다.

이 변경에 준비하기 위해 `ContainerRepositoryType`과 상호 작용하는 GraphQL 쿼리를 검토하고 업데이트하도록 권장합니다. `migrationState` 필드에 대한 모든 참조를 제거하고 애플리케이션 논리를 적절히 조정하세요.

### GraphQL에서 `previousStageJobsOrNeeds` 제거 {#remove-previousstagejobsorneeds-from-graphql}

- GitLab 17.0에서 발표
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/424417)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

GraphQL의 `previousStageJobsOrNeeds` 필드는 `previousStageJobs` 및 `needs` 필드로 대체되었으므로 제거됩니다.

### GraphQL 필드 `take_ownership_pipeline_schedule`을(를) PipelineSchedulePermissions의 `admin_pipeline_schedule`(으)로 바꾸기 {#replace-graphql-field-take_ownership_pipeline_schedule-with-admin_pipeline_schedule-in-pipelineschedulepermissions}

- GitLab 15.9에서 발표
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/391941)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

GraphQL 필드 `take_ownership_pipeline_schedule`은(는) 지원이 중단됩니다. 사용자가 파이프라인 일정의 소유권을 가질 수 있는지 여부를 확인하려면 `admin_pipeline_schedule` 필드를 대신 사용하세요.

### Yarn 프로젝트의 종속성 검사에서 취약성 해결 {#resolve-a-vulnerability-for-dependency-scanning-on-yarn-projects}

- GitLab 17.9에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/501308)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

종속성 검사를 위해 Gemnasium 분석기가 제공하는 Yarn 프로젝트에 대한 [취약성 해결](https://docs.gitlab.com/user/application_security/vulnerabilities/#resolve-a-vulnerability) 기능은 GitLab 17.9에서 지원이 중단됩니다.

이 기능은 Gemnasium 분석기를 사용할 때 계속 작동하지만 새 종속성 검사 분석기로 마이그레이션한 후에는 사용할 수 없습니다. [마이그레이션 가이드](https://docs.gitlab.com/user/application_security/dependency_scanning/migration_guide_to_sbom_based_scans/)에서 자세한 내용을 확인하세요

대체 기능은 [자동 수정 비전](https://gitlab.com/groups/gitlab-org/-/epics/7186)의 일부로 계획되었지만 제공 일정이 정해지지 않았습니다.

### 공개 API의 구독 관련 API 엔드포인트는 지원이 중단됨 {#subscription-related-api-endpoints-in-the-public-api-are-deprecated}

- GitLab 17.9에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/515371#note_2319368251)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

다음 엔드포인트가 공개 REST API에서 제거됩니다:

- `PUT /api/v4/user/:id/credit_card_validation`
- `POST /api/v4/namespaces/:namespace_id/minutes`
- `PATCH /api/v4/namespaces/:previous_namespace_id/minutes/move/:target_namespace_id`
- `GET /api/v4/namespaces/:namespace_id/subscription_add_on_purchase/:id`
- `PUT /api/v4/namespaces/:namespace_id/subscription_add_on_purchase/:id`
- `POST /api/v4/namespaces/:namespace_id/subscription_add_on_purchase/:id`
- `POST /api/v4/namespaces/:id/gitlab_subscription`
- `PUT /api/v4/namespaces/:id/gitlab_subscription`
- `PUT /api/v4/namespaces/:id`

이러한 엔드포인트는 GitLab.com의 구독 정보를 관리하기 위해 구독 포털에서 사용되고 있었습니다. 사용이 JWT 인증을 포함한 내부 엔드포인트로 대체되었으며 향후 Cells 아키텍처를 지원합니다. 공개 API의 엔드포인트가 제거되므로 실수로 다시 사용되지 않으며 기능 드리프트가 시작됨에 따라 유지 관리 부담이 줄어듭니다.

이 변경의 결과로 인한 영향은 없을 것으로 예상되며, 이는 내부적으로 사용되는 엔드포인트이기 때문입니다.

### `agentk` 컨테이너 레지스트리가 Cloud Native GitLab으로 이동 중 {#the-agentk-container-registry-is-moving-to-cloud-native-gitlab}

- GitLab 17.9에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent/-/issues/630)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

`agentk` 컨테이너 레지스트리를 [프로젝트 특정 레지스트리](https://gitlab.com/gitlab-org/cluster-integration/gitlab-agent/container_registry/1223205)에서 [Cloud Native GitLab(CNG) 레지스트리](https://gitlab.com/gitlab-org/build/CNG/container_registry/8241772)로 이동합니다. GitLab 18.0부터 CNG에서 빌드한 `agentk` 이미지가 프로젝트 특정 레지스트리로 미러링됩니다. 새 이미지는 이전 이미지와 동일하지만, 새 이미지는 `amd64` 및 `arm64` 아키텍처만 지원합니다. 32비트 `arm` 아키텍처는 지원되지 않습니다. GitLab 19.0부터 프로젝트 특정 레지스트리는 `agentk` 업데이트를 받지 않습니다. `agentk` 컨테이너를 로컬 레지스트리로 미러링하는 경우 미러 소스를 [CNG 레지스트리](https://gitlab.com/gitlab-org/build/CNG/container_registry/8241772)로 변경해야 합니다.

공식 [GitLab Agent Helm 차트](https://gitlab.com/gitlab-org/charts/gitlab-agent/)를 사용하는 경우 새 `agentk` 이미지가 GitLab 18.0에서 새 위치에서 원활하게 배포됩니다.

### CI/CD 작업 토큰을 JWT 표준으로 업데이트 {#updating-cicd-job-tokens-to-jwt-standard}

- GitLab 17.9에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/509578)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

GitLab 19.0에서 CI/CD 작업 토큰은 문자열 토큰 형식에서 JWT 토큰 형식으로 전환됩니다. 이 변경은 모든 프로젝트의 새로운 기존 CI/CD 작업 토큰에 영향을 미칩니다. 문제가 발생하면 GitLab 20.0 릴리스까지 여전히 [CI/CD 토큰에 기존 형식을 사용](https://docs.gitlab.com/ci/jobs/ci_job_token#use-legacy-format-for-cicd-tokens)할 수 있습니다.

알려진 문제:

1. GitLab Runner의 AWS Fargate 드라이버 0.5.0 이하는 JWT 표준과 호환되지 않습니다. 작업이 `file name too long` 오류로 실패합니다. [AWS Fargate 사용자 정의 실행기 드라이버](https://docs.gitlab.com/runner/configuration/runner_autoscale_aws_fargate/)의 사용자는 0.5.1 이상으로 업그레이드해야 합니다. 마이그레이션 지침은 [설명서](https://gitlab.com/gitlab-org/ci-cd/custom-executor-drivers/fargate/-/tree/master/docs)를 참조하세요.
1. 훨씬 긴 JWT 표준이 일부 CI/CD 구성 파일에서 사용되는 `echo $CI_JOB_TOKEN | base64` 명령을 중단합니다. `echo $CI_JOB_TOKEN | base64 -w0` 명령을 대신 사용할 수 있습니다.

### Gitaly의 `bin_path` 및 `use_bundled_binaries` 구성 옵션 {#bin_path-and-use_bundled_binaries-configuration-options-in-gitaly}

- GitLab 18.2에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/9181)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

Gitaly에서 `bin_path` 및 `use_bundled_binaries` 구성 옵션을 사용하는 지원은 지원 중단되었으며 GitLab 19.0에서 제거될 예정입니다.

Gitaly가 제공하는 Git 바이너리가 Git 실행을 지원하는 유일한 방법이 됩니다.

### `mergeTrainIndex` 및 `mergeTrainsCount` GraphQL 필드는 지원이 중단됨 {#mergetrainindex-and-mergetrainscount-graphql-fields-deprecated}

- GitLab 17.5에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/473759)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

GraphQL 필드 `mergeTrainIndex` 및 `mergeTrainsCount`은(는) `MergeRequest`에서 지원이 중단됩니다. 머지 트레인에서 머지 리퀘스트의 위치를 확인하려면 `MergeTrainCar`의 `index` 필드를 대신 사용하세요. 머지 트레인의 MR 수를 가져오려면 `MergeTrains::TrainType`의 `cars`에서 `count`을(를) 사용하세요.

### `scanResultPolicies` GraphQL 필드는 지원이 중단됨 {#scanresultpolicies-graphql-field-is-deprecated}

- GitLab 17.8에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/439199)를 참조하세요.

> [!note]
> 이 변경 사항은 원래 마일스톤에서 제거되었으며 재평가 중입니다.

16.10에서 스캔 결과 정책의 이름을 머지 리퀘스트 승인 정책으로 변경하여 정책 유형의 범위 및 기능 변경을 더 정확하게 반영하였습니다.

결과적으로 GraphQL 엔드포인트를 업데이트했습니다. `scanResultPolicies` 대신 `approvalPolicies`을(를) 사용하세요.

## 취소된 변경 사항 {#canceled-changes}

다음 변경 사항이 취소되었습니다.

### 컨테이너 검사 기본 심각도 임계값 설정: `medium` {#container-scanning-default-severity-threshold-set-to-medium}

- GitLab 17.9에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/515358)를 참조하세요.

> [!note]
> 이 변경 사항은 취소되었습니다.

컨테이너 검사 보안 기능은 많은 보안 발견을 생성하며 이 볼륨은 종종 엔지니어링 팀이 관리하기 어렵습니다. 심각도 임계값을 `medium`로 변경하여 사용자에게 더 합리적인 기본값을 제공하며, `medium` 이하의 심각도를 가진 모든 발견이 보고되지 않습니다. GitLab 18.0부터 `CS_SEVERITY_THRESHOLD` 환경 변수의 기본값은 `unknown` 대신 `medium`로 설정됩니다. 결과적으로 `low` 및 `unknown` 심각도 수준의 보안 발견은 기본적으로 더 이상 보고되지 않습니다. 결과적으로 이러한 심각도를 가진 모든 취약성이 기본 브랜치에서 이전에 보고되었다면 컨테이너 검사의 다음 실행 시 더 이상 감지되지 않은 것으로 표시됩니다. 이러한 발견을 계속 표시하려면 `CS_SEVERITY_THRESHOLD` 변수를 원하는 수준으로 구성해야 합니다.

### 라이선스 검사 CI/CD 아티팩트 보고서 유형 지원 중단 {#deprecate-license-scanning-cicd-artifact-report-type}

- GitLab 16.9에서 발표
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/439301)를 참조하세요.

> [!note]
> 이 변경 사항은 취소되었습니다.

CI/CD [아티팩트 보고서](https://docs.gitlab.com/ci/yaml/artifacts_reports/) 유형은 GitLab 16.9에서 지원이 중단되었으며 GitLab 18.0에서 제거됩니다. 이 키워드를 사용하는 CI/CD 구성은 GitLab 18.0에서 작동을 중단합니다.

아티팩트 보고서 유형은 GitLab 16.3의 기존 라이선스 검사 CI/CD 작업 제거로 인해 더 이상 사용되지 않습니다. 대신 [CycloneDX 파일의 라이선스 검사](https://docs.gitlab.com/user/compliance/license_scanning_of_cyclonedx_files/)를 사용해야 합니다.

### 지원 종료 SAST 작업이 CI/CD 템플릿에서 제거됨 {#end-of-support-sast-jobs-will-be-removed-from-the-cicd-template}

- GitLab 17.9에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/519133)를 참조하세요.

> [!note]
> 이 변경 사항은 취소되었습니다.

GitLab 18.0에서는 이전 릴리스에서 지원 종료에 도달한 분석기 작업을 제거하도록 SAST CI/CD 템플릿을 업데이트합니다. 다음 작업이 `SAST.gitlab-ci.yml` 및 `SAST.latest.gitlab-ci.yml`에서 제거됩니다:

- `bandit-sast`, which [reached End of Support in 15.4](#sast-analyzer-consolidation-and-cicd-template-changes)
- `brakeman-sast`, which [reached End of Support in 17.0](#sast-analyzer-coverage-changing-in-gitlab-170)
- `eslint-sast`, which [reached End of Support in 15.4](#sast-analyzer-consolidation-and-cicd-template-changes)
- `flawfinder-sast`, which [reached End of Support in 17.0](#sast-analyzer-coverage-changing-in-gitlab-170)
- `gosec-sast`, which [reached End of Support in 15.4](#sast-analyzer-consolidation-and-cicd-template-changes)
- `mobsf-android-sast`, which [reached End of Support in 17.0](#sast-analyzer-coverage-changing-in-gitlab-170)
- `mobsf-ios-sast`, which [reached End of Support in 17.0](#sast-analyzer-coverage-changing-in-gitlab-170)
- `nodejs-scan-sast`, which [reached End of Support in 17.0](#sast-analyzer-coverage-changing-in-gitlab-170)
- `phpcs-security-audit-sast`, which [reached End of Support in 17.0](#sast-analyzer-coverage-changing-in-gitlab-170)
- `security-code-scan-sast`, which [reached End of Support in 16.0](#sast-analyzer-coverage-changing-in-gitlab-160)

각 분석기가 지원 종료에 도달했을 때 작업 `rules`을(를) 업데이트하여 기본적으로 실행되지 않도록 하고 업데이트 출시를 중단했습니다. 그러나 이러한 작업을 계속 사용하도록 템플릿을 사용자 정의했거나 파이프라인에서 기존 작업을 사용했을 수 있습니다. 위의 작업에 종속되는 사용자 정의가 있는 경우 18.0으로 업그레이드하기 전에 [필요한 작업](https://gitlab.com/gitlab-org/gitlab/-/issues/519133#actions-required)을 수행하여 CI/CD 파이프라인의 중단을 피하세요.

### 보안 컨테이너 레지스트리의 공개 사용은 지원이 중단됨 {#public-use-of-secure-container-registries-is-deprecated}

- GitLab 17.4에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/470641)를 참조하세요.

> [!note]
> 이 변경 사항은 취소되었습니다.

`registry.gitlab.com/gitlab-org/security-products/` 아래의 컨테이너 레지스트리는 GitLab 18.0에서 더 이상 액세스할 수 없습니다. [GitLab 14.8부터](https://docs.gitlab.com/update/deprecations/#secure-and-protect-analyzer-images-published-in-new-location) 올바른 위치는 `registry.gitlab.com/security-products` 아래입니다(`gitlab-org`이(가) 주소에서 없음).

이 변경은 GitLab [취약성 스캐너](https://docs.gitlab.com/user/application_security/#vulnerability-scanner-maintenance)에 대한 릴리스 프로세스의 보안을 개선합니다.

사용자는 `registry.gitlab.com/security-products/` 아래의 동등한 레지스트리를 사용하는 것이 좋으며, 이는 GitLab 보안 스캐너 이미지의 표준 위치입니다. 관련 GitLab CI 템플릿은 이미 이 위치를 사용하므로 수정되지 않은 템플릿을 사용하는 사용자의 경우 변경이 필요하지 않습니다.

오프라인 배포는 [특정 스캐너 지침](https://docs.gitlab.com/user/application_security/offline_deployments/#specific-scanner-instructions)을 검토하여 필요한 스캐너 이미지를 미러링하기 위해 올바른 위치를 사용하고 있는지 확인해야 합니다.

### SAST 작업은 더 이상 전역 캐시 설정을 사용하지 않음 {#sast-jobs-no-longer-use-global-cache-settings}

- GitLab 17.9에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/512564)를 참조하세요.

> [!note]
> 이 변경 사항은 취소되었습니다.

GitLab 18.0에서 SAST 및 IaC 검사를 업데이트하여 명시적으로 기본적으로 [CI/CD 작업 캐시 사용을 비활성화](https://docs.gitlab.com/ci/caching/#disable-cache-for-specific-jobs)합니다.

이 변경은 다음의 CI/CD 템플릿에 영향을 미칩니다:

- SAST: `SAST.gitlab-ci.yml`.
- IaC 검사: `SAST-IaC.gitlab-ci.yml`.

이미 `latest` 템플릿 `SAST.latest.gitlab-ci.yml` 및 `SAST-IaC.latest.gitlab-ci.yml`을(를) 업데이트했습니다. 이러한 템플릿 버전에 대한 자세한 내용은 [안정적 및 최신 템플릿](https://docs.gitlab.com/user/application_security/sast/#stable-vs-latest-sast-templates)을 참조하세요.

캐시 디렉토리는 대부분의 프로젝트에서 검사 범위에 포함되지 않으므로 캐시를 가져오면 시간 초과 또는 거짓 양성 결과가 발생할 수 있습니다.

프로젝트를 검사할 때 캐시를 사용해야 하는 경우 프로젝트의 CI 구성에서 [`cache`](https://docs.gitlab.com/ci/yaml/#cache) 속성을 [재정의](https://docs.gitlab.com/user/application_security/sast/#overriding-sast-jobs)하여 이전 동작을 복원할 수 있습니다.

### 비밀 검사 분석기는 기본적으로 루트 사용자로 실행되지 않음 {#secret-detection-analyzer-doesnt-run-as-root-user-by-default}

- GitLab 17.9에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/476160)를 참조하세요.

> [!note]
> 이 변경 사항은 취소되었습니다.

비밀 검사 분석기에 대한 이 계획된 변경은 취소되었습니다. 기본적으로 루트 사용자를 여전히 사용할 수 있습니다.

### SpotBugs 검사의 일부로 프로젝트 빌드 지원 {#support-for-project-build-as-part-of-spotbugs-scans}

- GitLab 17.9에서 발표됨
- 이 변경 사항을 논의하거나 자세히 알아보려면 [기능 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/513409)를 참조하세요.

> [!note]
> 이 변경 사항은 취소되었습니다.

SpotBugs [SAST 분석기](https://docs.gitlab.com/user/application_security/sast/#supported-languages-and-frameworks)는 검사할 아티팩트가 없을 때 빌드를 수행할 수 있습니다. 이것은 일반적으로 간단한 프로젝트에서 잘 작동하지만 더 복잡한 빌드에서는 실패할 수 있습니다.

GitLab 18.0부터 SpotBugs 분석기 빌드 실패를 해결하려면 다음을 수행해야 합니다:

1. [프로젝트를 사전 컴파일](https://docs.gitlab.com/user/application_security/sast/#pre-compilation)합니다.
1. 검사하려는 아티팩트를 분석기에 전달합니다.

이것은 기능의 변경이 아니므로 명확히 하기 위해 이 공지를 "취소됨"으로 표시했습니다.

> [!disclaimer]
