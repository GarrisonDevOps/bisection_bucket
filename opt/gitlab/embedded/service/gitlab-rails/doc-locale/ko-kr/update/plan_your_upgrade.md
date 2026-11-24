---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 업그레이드하기 전에
description: 업그레이드하기 전에 수행할 단계입니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

GitLab 인스턴스를 업그레이드하기 전에 다음을 수행해야 합니다:

1. 업그레이드를 위해 사전 업그레이드 정보를 수집하여 준비합니다.
1. GitLab 자체를 업그레이드하기 전에 사전 업그레이드 단계를 수행합니다.

## 사전 업그레이드 정보 수집 {#gather-pre-upgrade-information}

업그레이드를 계획할 때:

1. [GitLab 릴리스 및 유지 보수 정책](../policy/maintenance.md)을 검토하세요.
1. [GitLab 업그레이드 노트](versions/_index.md)를 참조하여 다양한 GitLab 버전의 호환성을 확인하세요.
1. 필요한 경우 [대상 GitLab 버전과의 OS 호환성](../install/package/_index.md)을 확인하세요.
1. Geo를 사용하는 경우:
   - [Geo 업그레이드 설명서](../administration/geo/replication/upgrading_the_geo_sites.md)를 검토하세요.
   - [GitLab 업그레이드 노트](versions/_index.md)에서 Geo 관련 정보를 검토하세요.
   - [데이터베이스 업그레이드](https://docs.gitlab.com/omnibus/settings/database/#upgrading-a-geo-instance) 시 Geo 관련 단계를 검토하세요.
   - 각 Geo 사이트(주 사이트 및 각 보조 사이트)에 대한 업그레이드 및 롤백 계획을 생성합니다.
1. 인스턴스에 적합한 [업그레이드 경로](upgrade_paths.md)를 결정하고 필요한 업그레이드 중단을 포함합니다. 업그레이드 중단으로 인해 여러 업그레이드를 수행해야 할 수 있습니다.
1. [업그레이드 헬스 체크](#run-upgrade-health-checks)를 실행하여 잠재적 문제를 조기에 찾고 해결합니다. 일부 데이터베이스 문제는 해결 시간이 오래 걸리므로 데이터베이스 헬스 체크를 포함합니다.
1. 다음을 문서화하는 업그레이드 계획을 생성합니다:
   - 가능하고 필요한 경우 [무중단 업그레이드](zero_downtime.md)를 포함하여 인스턴스를 업그레이드하는 단계입니다.
   - 업그레이드가 순조롭지 않은 경우 [필요시 GitLab을 롤백](#create-a-rollback-plan-and-backup)하는 방법을 포함하여 수행할 단계입니다.
1. 프로덕션 환경의 클론에서 업그레이드 계획을 테스트합니다. 이는 계획되지 않은 중단의 위험을 줄이고 [잠재적으로 오래 실행되는 마이그레이션](background_migrations.md#execute-a-migration)의 기간을 측정할 수 있도록 도와줍니다.

모든 사전 업그레이드 정보를 수집한 후 사전 업그레이드 단계 수행으로 진행할 수 있습니다.

### 롤백 계획 및 백업 생성 {#create-a-rollback-plan-and-backup}

업그레이드 중에 문제가 발생할 수 있으므로 롤백 계획을 갖추는 것이 중요합니다. 적절한 롤백 계획은 GitLab 인스턴스를 마지막으로 작동하던 상태로 복원하는 명확한 경로를 생성하며 다음으로 구성됩니다:

- 인스턴스를 백업하는 프로세스입니다.
- 인스턴스를 복원하는 프로세스입니다.

필요하기 전에 롤백 계획을 테스트해야 합니다. 롤백에 필요한 단계에 대한 개요는 [이전 GitLab 버전으로 롤백](package/downgrade.md)을 참조하세요.

#### GitLab 백업 생성 {#create-a-gitlab-backup}

업그레이드 문제가 발생하는 경우 GitLab을 롤백할 수 있도록 하려면 다음 중 하나를 수행합니다:

- [GitLab 백업](../administration/backup_restore/_index.md)을 생성합니다. 설치 방법에 따라 지침을 따르고 [비밀번호 및 구성 파일](../administration/backup_restore/backup_gitlab.md#storing-configuration-files)을 백업해야 합니다.
- 인스턴스의 스냅샷을 생성합니다. 다중 노드 설치인 경우 모든 노드의 스냅샷을 생성해야 합니다. 이 프로세스는 GitLab Support의 범위를 벗어납니다.

#### GitLab 롤백 {#roll-back-gitlab}

프로덕션을 모방하는 테스트 환경이 있는 경우 복원을 테스트하여 모든 것이 예상대로 작동하는지 확인합니다.

GitLab 백업을 복원하려면:

1. [복원 전제 조건](../administration/backup_restore/restore_gitlab.md#restore-prerequisites)을 참조하세요. 가장 중요한 것은 백업된 GitLab 인스턴스와 새 GitLab 인스턴스의 버전이 동일해야 한다는 것입니다.
1. 설치 방법에 따라 지침을 따르면서 [GitLab을 복원](../administration/backup_restore/_index.md#restore-gitlab)합니다.
1. [비밀번호 및 구성 파일](../administration/backup_restore/backup_gitlab.md#storing-configuration-files)도 복원되었는지 확인하세요.

스냅샷에서 복원하는 경우 이미 이를 수행하는 방법을 알고 있어야 합니다. 이 프로세스는 GitLab Support의 범위를 벗어납니다.

## 사전 업그레이드 단계 수행 {#perform-pre-upgrade-steps}

업그레이드를 수행하기 직전:

1. [업그레이드 헬스 체크](#run-upgrade-health-checks)를 다시 실행하고 데이터베이스 헬스 체크를 포함합니다.
1. 사용 중인 [선택적 기능의 업그레이드](#upgrades-for-optional-features)를 수행합니다.

### 업그레이드 헬스 체크 실행 {#run-upgrade-health-checks}

업그레이드 직전과 직후에 업그레이드 헬스 체크를 실행하여 GitLab의 주요 구성 요소가 작동하는지 확인합니다:

1. [일반 구성 확인](../administration/raketasks/maintenance.md#check-gitlab-configuration):

   ```shell
   sudo gitlab-rake gitlab:check
   ```

1. [모든 백그라운드 데이터베이스 마이그레이션](background_migrations.md)의 상태를 확인합니다. 모든 마이그레이션은 각 업그레이드 전에 실행을 완료해야 합니다. 백그라운드 마이그레이션이 완료될 시간을 허용하기 위해 주요 및 부 릴리스 간 업그레이드를 분산해야 합니다.
1. 암호화된 데이터베이스 값을 [해독할 수 있는지](../administration/raketasks/check.md#verify-database-values-can-be-decrypted-using-the-current-secrets) 확인합니다:

   ```shell
   sudo gitlab-rake gitlab:doctor:secrets
   ```

1. [데이터베이스 헬스 체크](#check-database-health)합니다.
1. GitLab UI에서 다음을 확인합니다:
   - 사용자가 로그인할 수 있습니다.
   - 프로젝트 목록이 표시됩니다.
   - 프로젝트 이슈 및 머지 리퀘스트에 액세스할 수 있습니다.
   - 사용자가 GitLab에서 리포지토리를 복제할 수 있습니다.
   - 사용자가 GitLab에 커밋을 푸시할 수 있습니다.

1. GitLab CI/CD의 경우 다음을 확인합니다:
   - 러너가 작업을 선택합니다.
   - Docker 이미지를 레지스트리에서 푸시하고 가져올 수 있습니다.

1. Geo를 사용하는 경우 주 사이트 및 각 보조 사이트에서 관련 체크를 실행합니다:

   ```shell
   sudo gitlab-rake gitlab:geo:check
   ```

1. Elasticsearch를 사용하는 경우 검색이 성공하는지 확인하세요.
1. 선택사항. [공식 저장소에서 패키지 사전 다운로드](package/_index.md#pre-download-a-package-from-the-official-repository)하여 패키지 가용성을 테스트하고 설치 시간을 줄입니다.

문제가 발생하면 [지원 받기](#get-support)를 참조하세요.

### 데이터베이스 헬스 체크 {#check-database-health}

데이터베이스 마이그레이션은 업그레이드 중에 실행됩니다. 데이터베이스 스키마가 현재 GitLab 버전의 스키마와 일치하고 변경하는 테이블에 대한 잠금이 필요합니다. 데이터베이스 진단 페이지를 사용하여 마이그레이션 실패를 야기할 수 있는 문제를 찾습니다.

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

데이터베이스 헬스를 확인하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **모니터링** > **데이터베이스 진단**을 선택합니다.
1. **스키마 헬스 점검** 섹션에서 **스키마 검사 실행**을 선택합니다. 체크는 백그라운드 작업으로 실행되므로 Sidekiq을 실행 중이어야 합니다. 작업이 완료되면 페이지에 결과가 표시됩니다. 결과는 1주일 동안 사용 가능합니다. 업그레이드하기 직전에 체크를 다시 실행하세요.
1. 결과를 검토하고 업그레이드하기 전에 조치를 취하세요:

   | 섹션   | 문제   | 작업   |
   |-----------|-----------|----------|
   | **스키마 헬스 점검** | 체크에서 누락된 테이블, 인덱스, 외래 키 또는 시퀀스 또는 잘못된 시퀀스 소유자를 보고합니다. 이러한 개체에 따라 달라지는 마이그레이션이 실패할 수 있습니다. | 자동 복구 도구를 사용할 수 없습니다. 업그레이드하기 전에 GitLab Support에 문의하세요. 자세한 내용은 [스키마 헬스 점검](../administration/admin_area.md#schema-health-check)을 참조하세요. |
   | **검색 경로** | 검색 경로에 GitLab 개체가 포함된 스키마가 1개 이상 있다는 오류가 보고됩니다. 마이그레이션이 잘못된 스키마의 개체를 변경할 수 있습니다. | 업그레이드하기 전에 검색 경로의 주 스키마에만 GitLab 개체가 포함되어 있는지 확인하세요. 도움을 받으려면 GitLab Support에 문의하세요. 자세한 내용은 [검색 경로 체크](../administration/admin_area.md#search-path-check)를 참조하세요. |
   | **Vacuum 정보** | Vacuum에 **랩어라운드 방지** 배지가 있습니다. 이 Vacuum은 자체 취소되지 않으므로 마이그레이션이 잠금을 대기하고 실패할 수 있습니다. | 업그레이드를 시작하지 말고 Vacuum을 중지하지 마세요. Vacuum이 완료될 때까지 기다리세요. 자세한 내용은 [자동 Vacuum 모니터링](../administration/postgresql/vacuum.md#database-diagnostics-page)을 참조하세요. |

**Vacuum 정보** 섹션에서 지금 실행 중인 Vacuum을 표시합니다. 업그레이드를 시작하기 직전에 이 섹션을 다시 확인하세요.

UI에 액세스할 수 없는 경우 콘솔에서 검색 경로를 확인할 수 있습니다:

```shell
sudo gitlab-rake gitlab:db:diagnostics:search_path
```

오류를 찾으면 작업이 상태 `1`로 종료됩니다.

### 선택적 기능의 업그레이드 {#upgrades-for-optional-features}

GitLab 인스턴스 구성 방식에 따라 GitLab을 업그레이드하기 전에 이러한 추가 단계를 수행해야 할 수 있습니다:

1. 외부 Gitaly 서버를 사용하는 경우 GitLab 자체를 업그레이드하기 전에 Gitaly 서버를 최신 버전으로 업그레이드합니다. 이렇게 하면 애플리케이션 서버의 gRPC 클라이언트가 이전 Gitaly 버전에서 지원하지 않는 RPC를 보내는 것을 방지합니다.
1. GitLab에 연결된 Kubernetes 클러스터가 있는 경우 [Kubernetes용 GitLab 에이전트를 업그레이드](../user/clusters/agent/install/_index.md#update-the-agent-version)하여 새로운 GitLab 버전과 일치시킵니다.
1. 고급 검색(Elasticsearch)을 사용하는 경우 [보류 중인 마이그레이션 확인](background_migrations.md#check-for-pending-advanced-search-migrations)을 통해 고급 검색 마이그레이션이 완료되었는지 확인합니다. [`gitlab:check` Rake 작업](../integration/advanced_search/elasticsearch.md#all-migrations-must-be-finished-before-doing-a-major-upgrade)도 보류 중인 고급 검색 마이그레이션이 있는지 보고합니다. 체크는 업그레이드를 중지하지 않으므로 출력을 읽고 결과에 따라 조치를 취해야 합니다.

   GitLab을 업그레이드한 후 [새 버전이 호환성을 손상시키는 경우 Elasticsearch를 업그레이드](../integration/advanced_search/elasticsearch.md#version-compatibility)해야 할 수 있습니다. Elasticsearch 업데이트는 GitLab Support의 범위를 벗어납니다.

## CI/CD 파이프라인 및 작업 일시 중지 {#pause-cicd-pipelines-and-jobs}

대부분의 GitLab 인스턴스 유형에 대한 업그레이드 중에는 CI/CD 파이프라인 및 작업을 일시 중지해야 합니다.

GitLab Runner가 작업을 처리하는 동안 GitLab 인스턴스를 업그레이드하면 추적 업데이트가 실패합니다. GitLab이 다시 온라인 상태가 되면 추적 업데이트가 자체적으로 복구되어야 합니다. 추적 업데이트가 자체적으로 복구되지 않는 경우 오류에 따라 GitLab Runner가 다시 시도하거나 작업 처리를 종료합니다.

GitLab Runner는 작업 아티팩트를 3회 업로드하려고 시도하며, 그 후 작업이 실패합니다.

CI/CD 파이프라인 및 작업을 일시 중지하려면:

1. 러너를 일시 중지합니다.
1. `/etc/gitlab/gitlab.rb` 파일에 다음을 추가하여 새 작업이 시작되는 것을 차단합니다:

   ```ruby
   nginx['custom_gitlab_server_config'] = "location = /api/v4/jobs/request {\n deny all;\n return 503;\n}\n"
   ```

1. GitLab을 재구성합니다.

   ```shell
   sudo gitlab-ctl reconfigure
   ```

1. 모든 작업이 완료될 때까지 기다립니다.

GitLab 업그레이드를 완료한 경우:

1. 러너를 일시 중지 해제합니다.
1. 이전 `/etc/gitlab/gitlab.rb` 변경 사항을 되돌려 새 작업이 시작되는 것을 차단 해제합니다.

## Support와 함께 작업 {#working-with-support}

업그레이드 계획을 검토하기 위해 [Support와 함께 작업](https://about.gitlab.com/support/scheduling-upgrade-assistance/)하는 경우 다음 질문에 대한 답변으로 문서화하고 공유하세요:

- GitLab은 어떻게 설치되었나요?
- 노드의 운영 체제는 무엇입니까? [지원되는 플랫폼](../install/package/_index.md#supported-platforms)을 확인하여 이후 업데이트를 사용할 수 있는지 확인하세요.
- 단일 노드 설정인가요, 아니면 다중 노드 설정인가요? 다중 노드인 경우 각 노드에 대한 아키텍처 세부 정보를 문서화하고 공유하세요. 어떤 외부 구성 요소가 사용되나요? 예를 들어 Gitaly, PostgreSQL 또는 Redis입니까?
- [Geo](../administration/geo/_index.md)를 사용 중입니까? 그렇다면 각 보조 사이트에 대한 아키텍처 세부 정보를 문서화하고 공유하세요.
- 설정에서 고유하거나 흥미로울 수 있는 다른 것이 있나요?
- 현재 GitLab 버전과 관련된 알려진 문제가 발생하고 있나요?
- 데이터베이스 헬스 체크는 무엇을 보고합니까? 데이터베이스 진단 보고서를 파일에 저장하고 **스키마 헬스 점검**의 결과가 포함된 파일을 공유하세요:

  ```shell
  sudo gitlab-rake gitlab:db:diagnostics > db_diagnostics.txt
  ```

## 지원 받기 {#get-support}

업그레이드 중 문제가 발생하면:

1. 오류를 복사하고 나중에 분석할 로그를 수집합니다. 데이터를 수집하는 데 도움이 되는 다음 도구를 사용합니다:
   - [`gitlabsos`](https://gitlab.com/gitlab-com/support/toolbox/gitlabsos): Linux 패키지 또는 Docker를 사용하여 GitLab을 설치한 경우입니다.
   - [`kubesos`](https://gitlab.com/gitlab-com/support/toolbox/kubesos/): Helm 차트를 사용하여 GitLab을 설치한 경우입니다.
   - `sudo gitlab-rake gitlab:db:diagnostics > db_diagnostics.txt`: 문제가 데이터베이스와 관련된 경우입니다.
1. 마지막으로 작동하는 버전으로 롤백합니다.

지원을 위해:

- [GitLab Support에 문의](https://support.gitlab.com/hc/en-us)하고 고객 성공 관리자에게 연락하세요(있는 경우).
- [상황이 적격](https://support.gitlab.com/hc/en-us/articles/11626416629660-Definitions#definitions-of-support-impact)이고 [계획에 긴급 지원이 포함](https://support.gitlab.com/hc/en-us/articles/11626483177756-GitLab-Support#priority-support)된 경우 긴급 티켓을 생성합니다.
