---
stage: GitLab Dedicated
group: Environment Automation
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "인스턴스가 프로모션된 후 버전 캐치업, 기능 활성화 및 라이선스 적용."
title: 마이그레이션 후 활동
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab Dedicated

{{< /details >}}

GitLab Dedicated 인스턴스가 기본 사이트로 프로모션된 후 예정된 활동들의 시퀀스에 따라 여러 기능이 활성화되며, 이는 귀사와 함께 조율됩니다. 이러한 활동들은 프로모션 전이 아닌 후에 발생합니다. 왜냐하면 인스턴스가 Geo 보조 사이트인 동안 실행될 수 없거나 마이그레이션 성공을 확인할 때까지 의도적으로 지연되기 때문입니다.

GitLab은 라이선스 추가를 제외한 이러한 모든 활동을 수행하며, 라이선스 추가는 귀사가 직접 수행합니다. 각 활동은 사후 커트오버 검증이 완료되고 인스턴스가 커트오버로 인한 열린 이슈 없이 사용자에게 서비스를 제공한 후에만 시작됩니다. 귀사의 Professional Services 마이그레이션 팀이 일정을 귀사와 함께 조율합니다.

## 버전 캐치업 {#version-catch-up}

프로덕션 전 커트오버부터 프로덕션 커트오버까지 업그레이드가 중단됩니다. 이 중단은 두 환경을 동일한 버전으로 유지하므로 테스트한 것이 실제로 얻는 것입니다.

이 중단으로 인해 인스턴스가 프로모션될 때 GitLab Dedicated 플릿의 나머지 부분보다 한 버전 뒤의 버전으로 실행됩니다. GitLab Dedicated는 현재 GitLab 릴리스를 기준으로 이전 마이너 버전(N-1)을 실행합니다. 자세한 정보는 [버전 관리 모델](../releases.md#versioning-model)을 참조하세요.

캐치업은 의도적이고 순차적인 작업입니다. 인스턴스는 단일 점프가 아닌 여러 유지보수 윈도우에 걸쳐 중간 버전을 거쳐 업그레이드됩니다. 이러한 각 업그레이드는 [무중단 업그레이드](../maintenance.md#zero-downtime-upgrades)이므로 캐치업이 사용자에 대한 반복된 중단을 의미하지 않습니다.

업그레이드 경로에는 필수 중간 버전이 포함될 수 있습니다. 경로에 포함된 버전을 확인하려면 [업그레이드 경로 도구](https://gitlab-com.gitlab.io/support/toolbox/upgrade-path/)를 사용하세요.

GitLab은 캐치업이 완료된 후 주간 유지보수 윈도우를 다시 활성화합니다. 그 이후로 인스턴스는 다른 GitLab Dedicated 인스턴스와 같은 표준 월간 릴리스 주기를 따릅니다. 자세한 정보는 [유지보수 윈도우](../maintenance.md#maintenance-windows) 및 [릴리스 롤아웃 일정](../releases.md#release-rollout-schedule)을 참조하세요.

GitLab Dedicated 버전 일정을 추적하려면 [GitLab Dedicated 정보 포털](https://gitlab-com.gitlab.io/cs-tools/gitlab-cs-tools/dedicated-info-portal/)을 사용하세요.

> [!note]
> 캐치업 기간 동안 인스턴스는 다른 GitLab Dedicated 인스턴스보다 이전 버전을 실행할 수 있습니다. 이 차이는 예상되며 임시적입니다.

## 고급 검색 {#advanced-search}

고급 검색은 GitLab Dedicated에서 완전히 지원되며 GitLab은 검색 인프라를 프로비저닝하고 관리합니다.

Geo는 고급 검색 인덱스를 복제하지 않으므로 인스턴스가 Geo 보조 사이트인 동안에는 인덱스를 빌드할 수 없습니다. 따라서 GitLab은 프로모션 후 귀사와 함께 조율한 시간에 고급 검색을 활성화하고 콘텐츠를 인덱싱합니다. 소스 인스턴스의 기존 검색 클러스터는 마이그레이션되지 않습니다. 인덱싱이 실행되는 동안 기본 검색은 계속 사용 가능합니다.

자세한 정보는 [고급 검색](../../../integration/advanced_search/elasticsearch.md)을 참조하세요.

## 고급 분석 {#advanced-analytics}

고급 분석 기능은 ClickHouse Cloud에 의해 지원됩니다. 인스턴스가 프로모션될 때 이러한 기능은 활성화되지 않습니다. GitLab은 커트오버 후 별도의 예정된 단계에서 이를 활성화합니다.

가용성은 기본 지역에 따라 달라집니다. ClickHouse Cloud는 지원되는 지역에서만 사용 가능하기 때문입니다. 자세한 정보는 [ClickHouse Cloud 지역](../create_instance/data_residency_high_availability.md#clickhouse-cloud)을 참조하세요.

통합이 제공하는 사항은 [ClickHouse](../../../integration/clickhouse.md)를 참조하세요.

## 재해 복구를 위한 Geo 보조 사이트 {#geo-secondary-site-for-disaster-recovery}

마이그레이션 중에 GitLab Dedicated 인스턴스는 단일 사이트로 실행됩니다. 보조 지역은 구성되지 않습니다. 인스턴스 자체가 소스 인스턴스의 Geo 보조 사이트로 작동하기 때문입니다. 따라서 표준 GitLab Dedicated Geo 재해 복구 토폴로지는 마이그레이션 중에는 적절하지 않습니다.

GitLab은 마이그레이션이 완료된 후 보조 사이트를 추가합니다. 보조 사이트를 추가하는 것은 의도적인 단계입니다. 추가된 후에는 이전 복제 배열로 돌아갈 수 없기 때문입니다. 보조 사이트가 추가된 후 인스턴스는 다른 GitLab Dedicated 인스턴스와 동일한 재해 복구 태세를 가집니다.

자세한 정보는 [재해 복구를 위한 Geo 복제](../disaster_recovery.md#geo-replication)를 참조하세요.

> [!note]
> 자동화된 백업은 마이그레이션 중을 포함하여 계속 적용됩니다. 자세한 정보는 [자동화된 백업](../disaster_recovery.md#automated-backups)을 참조하세요.

## 러너 및 CI/CD {#runners-and-cicd}

러너 등록 기록은 데이터베이스에 저장되며 데이터베이스가 마이그레이션되므로 기존 러너가 보존됩니다.

고유한 도메인을 유지하면 인스턴스 호스트명이 변경되지 않으며 러너는 구성 변경 없이 GitLab Dedicated에 다시 연결됩니다. GitLab에서 제공하는 도메인으로 이동하면 러너 구성에서 인스턴스 URL을 업데이트합니다.

훨씬 이전 GitLab 버전의 러너는 재연결 지연을 경험할 수 있습니다. 커트오버를 부드럽게 유지하려면 마이그레이션 윈도우 전에 자체 관리 러너를 현재 버전으로 업그레이드합니다.

자세한 정보는 [페일오버 중 러너 연결](../../geo/disaster_recovery/planned_failover.md#runner-connectivity-during-failover)을 참조하세요.

GitLab에서 관리하는 러너는 [호스팅된 러너](../hosted_runners.md)를 참조하세요.

## 통합 및 인증 {#integrations-and-authentication}

통합, 웹후크 및 아웃바운드 연결은 프로덕션 전 [테스트 기간](process.md#testing-period) 동안 검증됩니다. 프로덕션 커트오버 후 프로덕션 인스턴스에 대해 동일한 통합을 확인합니다.

다음 항목들을 확인합니다:

- Single Sign-On
- 내부 대상으로의 웹후크 전달
- 이메일 전달
- 러너 및 Kubernetes 클러스터에서의 컨테이너 레지스트리 액세스
- AWS PrivateLink 아웃바운드를 통해 개인 대상에 도달하는 모든 통합
- 인스턴스를 호출하는 모든 외부 SaaS 서비스(차단 목록을 사용하는 경우 IP 차단 목록 예외가 필요함)

새 Kubernetes용 GitLab 에이전트 서버(KAS) URL에 대해 Kubernetes용 GitLab 에이전트를 다시 등록해야 합니다.

## GitLab Dedicated 라이선스 추가 {#add-your-gitlab-dedicated-license}

커트오버 후 GitLab Dedicated 라이선스를 추가해야 합니다.

마이그레이션 중에 데이터베이스는 GitLab Self-Managed 인스턴스의 라이선스를 전달합니다. GitLab이 데이터베이스의 나머지 부분과 함께 라이선스 정보를 복제하기 때문입니다. 해당 라이선스는 GitLab Dedicated 구독을 포함하지 않습니다.

라이선스 담당자가 GitLab Dedicated의 활성화 코드를 받고 프로모션된 인스턴스에서 활성화해야 합니다. 자세한 정보는 [라이선스 키 추가](../../license_file.md#add-license-in-the-admin-area)를 참조하세요.

활성화 코드를 받지 못했거나 활성화가 실패한 경우 GitLab 계정 팀에 문의하세요.

## 관련 항목 {#related-topics}

- [GitLab Dedicated로의 Geo 마이그레이션](_index.md)
- [Geo 마이그레이션 요구 사항](requirements.md)
- [Geo 마이그레이션 프로세스](process.md)
