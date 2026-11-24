---
stage: Application Security Testing
group: Composition Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 패키지 메타데이터 데이터베이스
description: "패키지 메타데이터 데이터베이스의 콘텐츠, GitLab이 이를 동기화하는 방식, 각 GitLab 버전이 읽는 데이터 형식 버전."
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

패키지 메타데이터 데이터베이스(PMDB)는 GitLab이 관리하는 오픈소스 패키지의 라이선스 및 보안 자문 데이터 모음입니다. GitLab은 이를 인스턴스의 데이터베이스에 동기화하며, 다음 기능이 이를 읽습니다:

- [레지스트리의 컨테이너 검사](../container_scanning/_index.md#container-scanning-for-registry)
- [지속적인 취약성 검사](../continuous_vulnerability_scanning/_index.md)
- [종속성 검사](../dependency_scanning/_index.md)
- [CycloneDX 파일의 라이선스 검사](../../compliance/license_scanning_of_cyclonedx_files/_index.md)

패키지 메타데이터 데이터베이스는 [EE 라이선스](https://storage.googleapis.com/prod-export-license-bucket-1a6c642fc4de57d4/LICENSE)에 따라 라이선스가 부여됩니다.

## 데이터세트 {#datasets}

{{< history >}}

- 악성코드 자문은 GitLab 19.3에서 [베타](../../../policy/development_stages_support.md#beta)로 [도입되었으며](https://gitlab.com/groups/gitlab-org/-/epics/20876) [플래그](../../../administration/feature_flags/_index.md)는 `sync_malware_advisories`와 `ingest_malware_advisories`로 명명되었습니다. 기본적으로 활성화되어 있습니다.
- v3 라이선스 데이터는 GitLab 19.4에서 [도입되었으며](https://gitlab.com/groups/gitlab-org/-/epics/22880) `sync_v3_license_expressions` 플래그로 명명되었습니다. 기본적으로 활성화되어 있습니다.
- 악성코드 자문은 GitLab 19.5에서 [일반적으로 사용 가능](https://gitlab.com/groups/gitlab-org/-/epics/20876)합니다. 기능 플래그 `sync_malware_advisories` 및 `ingest_malware_advisories`이 제거되었습니다.

{{< /history >}}

패키지 메타데이터 데이터베이스는 4개의 데이터세트를 포함합니다:

| 데이터세트            | 콘텐츠                                              | 사용 대상 |
|--------------------|-------------------------------------------------------|---------|
| 라이선스           | 패키지 버전의 라이선스 데이터.                    | 라이선스 검사 |
| 자문         | 패키지 버전의 보안 자문.             | 종속성 검사, 지속적인 취약성 검사 및 레지스트리의 컨테이너 검사 |
| CVE 강화     | 취약성의 EPSS 점수 및 KEV 상태.     | [취약성 위험 평가 데이터](../vulnerabilities/risk_assessment_data.md) |
| 악성코드 자문 | 패키지 레지스트리에서 발견된 알려진 악성 패키지. | 종속성 검사, 지속적인 취약성 검사 및 머지 리퀘스트 승인 정책. 자세한 내용은 [악성코드에 대한 GitLab 자문](../gitlab_advisory_database/_index.md#gitlab-advisories-for-malware)을 참조하세요. |

기본적으로 GitLab은 모든 패키지 레지스트리 유형에 대한 데이터를 동기화합니다. 더 적은 데이터를 동기화하려면 사용하지 않는 패키지 레지스트리 유형을 [관리자 설정](../../../administration/settings/security_and_compliance.md#choose-package-registry-metadata-to-sync)에서 제거하세요.

## 데이터 형식 버전 {#data-format-versions}

각 데이터세트는 v2 또는 v3의 두 가지 데이터 형식 버전 중 하나로 게시됩니다. 이는 GitLab 버전이 아닌 데이터 형식의 버전입니다.

| 형식 버전 | 데이터세트 | 배포 출처 |
|----------------|----------|------------------|
| v2             | GitLab 19.3 이전 버전의 라이선스, 자문 및 CVE 강화. | 공개 Google Cloud Storage 버킷, 인증 없이 읽을 수 있습니다. |
| v3             | GitLab 19.4 이상의 라이선스 및 악성코드 자문. | 패키지 메타데이터 데이터베이스 배포 서비스, 인증된 GitLab 서비스. |

v3 라이선스 데이터는 단일 라이선스 식별자 대신 SPDX(Software Package Data Exchange) 라이선스 표현을 포함합니다. 예를 들어, `MIT OR Apache-2.0`입니다.

형식 버전을 선택하지 않습니다. GitLab 버전이 읽는 것을 결정합니다:

| GitLab 버전   | 라이선스 | 자문 | CVE 강화 | 악성코드 자문 |
|------------------|----------|------------|----------------|--------------------|
| 19.2 이전 버전 | v2       | v2         | v2             | 사용할 수 없음      |
| 19.3             | v2       | v2         | v2             | v3                 |
| 19.4 이상   | v3       | v2         | v2             | v3                 |

## 동기화 {#synchronization}

Sidekiq의 Cron 작업은 각 데이터세트를 인스턴스의 데이터베이스에 동기화합니다. 각 실행은 이전 실행이 기록한 체크포인트에서 재개되므로 인스턴스가 이미 보유한 데이터보다 최신 데이터만 가져옵니다.

### 인터넷 액세스가 있는 인스턴스 {#instances-with-internet-access}

인터넷에 액세스할 수 있는 인스턴스는 공개 버킷에서 v2 데이터를 다운로드하고 배포 서비스에서 v3 데이터를 다운로드합니다. v2 데이터를 다운로드하려면 인스턴스는 `storage.googleapis.com`에 대한 아웃바운드 네트워크 액세스가 필요합니다.

### 오프라인 인스턴스 {#offline-instances}

오프라인 인스턴스는 데이터 자체를 다운로드할 수 없습니다. 대신 인터넷에 액세스할 수 있는 컴퓨터에서 데이터를 다운로드하여 오프라인 인스턴스의 `vendor/package_metadata` 디렉터리로 복사합니다. v3 데이터를 다운로드하려면 오프라인 라이선스가 필요합니다.

`vendor/package_metadata`에서 데이터세트의 디렉터리가 존재하면 GitLab은 데이터를 다운로드하는 대신 해당 디렉터리를 읽습니다. 네트워크에 대한 폴백이 없으므로 이전 데이터를 포함하는 디렉터리는 이전 데이터를 제공하고 오류를 보고하지 않습니다.

각 데이터세트의 다운로드 절차 및 기능 플래그 세부 정보는 [오프라인 인스턴스용 패키지 메타데이터 데이터베이스](../../../topics/offline/package-metadata-database.md)를 참조하세요.

## 관련 항목 {#related-topics}

- [오프라인 환경](../offline_deployments/_index.md)
