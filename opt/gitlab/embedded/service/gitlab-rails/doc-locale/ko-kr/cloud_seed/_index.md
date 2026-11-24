---
stage: none
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
ignore_in_report: true
title: Cloud Seed
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 15.4에 [도입되었으며](https://gitlab.com/gitlab-org/gitlab/-/issues/371332) [기능 플래그](../administration/feature_flags/_index.md)의 이름은 `google_cloud`입니다. 기본적으로 비활성화되었습니다.
- GitLab 15.5에 [GitLab Self-Managed 및 GitLab.com에서 활성화되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/100545).

{{< /history >}}

Cloud Seed는 [Google Cloud](https://cloud.google.com/)와의 협력으로 GitLab이 주도하는 오픈소스 프로그램입니다.

Cloud Seed는 Heroku와 유사한 사용 편의성과 하이퍼 클라우드 유연성을 결합합니다. OAuth 2를 사용하여 Terraform 및 코드 기반 인프라의 기초 위에 하이퍼 클라우드에서 서비스를 프로비저닝하여 2일 차 운영을 지원합니다.

## 목적 {#purpose}

GitLab에서 웹 애플리케이션(및 기타 워크로드)을 주요 클라우드 공급자에게 배포하는 것이 간단해야 한다고 생각합니다.

이러한 노력을 지원하기 위해 Cloud Seed는 GitLab에서 적절한 Google Cloud 서비스를 사용하기 간단하고 직관적으로 만듭니다.

## Google Cloud를 선택한 이유 {#why-google-cloud}

*또는 AWS나 Azure는 안 되나요?*

Cloud Seed는 누구나 확장할 수 있는 오픈소스 프로그램이며, 모든 주요 클라우드 공급자와 협력하고 싶습니다. Google Cloud를 선택한 이유는 그들의 팀이 이 노력에서 접근하기 쉽고, 지지하며, 협력적이기 때문입니다.

오픈소스 프로젝트로서 [모든 사람이 기여할 수 있으며](#contribute-to-cloud-seed) 저희의 방향을 결정합니다.

## Google Cloud Run에 배포 {#deploy-to-google-cloud-run}

GitLab 프로젝트에 웹 애플리케이션이 있으면 다음 단계를 따라 Cloud Seed를 사용하여 GitLab에서 Google Cloud로 애플리케이션을 배포합니다:

1. [배포 자격 증명 설정](#set-up-deployment-credentials)
1. (선택 사항) [선호하는 GCP 영역 구성](#configure-your-preferred-gcp-region)
1. [Cloud Run 배포 파이프라인 구성](#configure-the-cloud-run-deployment-pipeline)

### 배포 자격 증명 설정 {#set-up-deployment-credentials}

Cloud Seed는 GitLab 프로젝트에서 Google Cloud Platform(GCP) 서비스 계정을 생성할 수 있는 인터페이스를 제공합니다. 서비스 계정 생성 워크플로 중에 연결된 GCP 프로젝트를 선택해야 합니다. 이 프로세스는 서비스 계정, 키 및 배포 권한을 생성합니다.

서비스 계정을 생성하려면:

1. `Project :: Infrastructure :: Google Cloud` 페이지로 이동합니다.
1. **서비스 계정 생성**을 선택합니다.
1. Google OAuth 2 워크플로를 따르고 GitLab을 승인합니다.
1. GCP 프로젝트를 선택합니다.
1. 선택한 GCP 프로젝트에 대해 Git 참조(예: 브랜치 또는 태그)를 연결합니다.
1. 양식을 제출하여 서비스 계정을 생성합니다.

생성된 서비스 계정, 서비스 계정 키 및 연결된 GCP 프로젝트 ID는 GitLab에 프로젝트 CI 변수로 저장됩니다. `Project :: Settings :: CI` 페이지에서 이를 검토하고 관리할 수 있습니다.

생성된 서비스 계정에는 다음 역할이 있습니다:

- `roles/iam.serviceAccountUser`
- `roles/artifactregistry.admin`
- `roles/cloudbuild.builds.builder`
- `roles/run.admin`
- `roles/storage.admin`
- `roles/cloudsql.client`
- `roles/browser`

CI 변수를 시크릿 매니저에 저장하여 보안을 강화할 수 있습니다. 자세한 내용은 [GitLab의 시크릿 관리](../ci/secrets/_index.md)를 참조하세요.

### 선호하는 GCP 영역 구성 {#configure-your-preferred-gcp-region}

배포를 위해 GCP 영역을 구성할 때, 제공되는 영역 목록은 사용 가능한 모든 GCP 영역의 하위 집합입니다.

영역을 구성하려면:

1. `Project :: Infrastructure :: Google Cloud` 페이지로 이동합니다.
1. **GCP 영역 구성**을 선택합니다.
1. 선호하는 GCP 영역을 선택합니다.
1. 선택한 GCP 영역에 대해 Git 참조(예: 브랜치 또는 태그)를 연결합니다.
1. 양식을 제출하여 GCP 영역을 구성합니다.

구성된 GCP 영역은 GitLab에 프로젝트 CI 변수로 저장됩니다. `Project :: Settings :: CI` 페이지에서 이를 검토하고 관리할 수 있습니다.

### Cloud Run 배포 파이프라인 구성 {#configure-the-cloud-run-deployment-pipeline}

파이프라인에서 Google Cloud Run 배포 작업을 구성할 수 있습니다. 이러한 파이프라인의 일반적인 사용 사례는 웹 애플리케이션의 지속적 배포입니다.

프로젝트 파이프라인 자체는 빌드, 테스트 및 보안과 같은 여러 스테이지에 걸쳐 더 광범위한 목적을 가질 수 있습니다. 따라서 Cloud Run 배포 제공 서비스는 훨씬 더 큰 파이프라인에 적합한 한 가지 작업으로 패키지됩니다.

Cloud Run 배포 파이프라인을 구성하려면:

1. `Project :: Infrastructure :: Google Cloud` 페이지로 이동합니다.
1. `Deployments` 탭으로 이동합니다.
1. `Cloud Run`에서 **머지 리퀘스트를 통해 설정**을 선택합니다.
1. 변경 사항을 검토하고 제출하여 머지 리퀘스트를 생성합니다.

Cloud Run 배포 파이프라인이 있는 새로운 브랜치(또는 기존 파이프라인에 삽입)를 생성하고, 변경 사항 및 배포 파이프라인 실행을 검토하고 메인 브랜치로 병합할 수 있는 연결된 머지 리퀘스트를 생성합니다.

## Cloud SQL 데이터베이스 프로비저닝 {#provision-cloud-sql-databases}

`Project :: Infrastructure :: Google Cloud` 페이지에서 관계형 데이터베이스 인스턴스를 프로비저닝할 수 있습니다. Cloud SQL은 데이터베이스 인스턴스를 프로비저닝하는 데 사용되는 기본 Google Cloud 서비스입니다.

다음 데이터베이스 및 버전이 지원됩니다:

- PostgreSQL: 14, 13, 12, 11, 10, 9.6
- MySQL: 8.0, 5.7, 5.6
- SQL Server
  - 2019: Standard, Enterprise, Express, Web
  - 2017: Standard, Enterprise, Express, Web

Google Cloud 가격이 적용됩니다. [Cloud SQL 가격 책정 페이지](https://cloud.google.com/sql/pricing)를 참조하세요.

1. [데이터베이스 인스턴스 생성](#create-a-database-instance)
1. [백그라운드 워커를 통한 데이터베이스 설정](#database-setup-through-a-background-worker)
1. [데이터베이스에 연결](#connect-to-the-database)
1. [데이터베이스 인스턴스 관리](#managing-the-database-instance)

### 데이터베이스 인스턴스 생성 {#create-a-database-instance}

`Project :: Infrastructure :: Google Cloud` 페이지에서 **데이터베이스** 탭을 선택합니다. Postgres, MySQL 및 SQL Server 데이터베이스 인스턴스를 생성할 수 있는 세 개의 버튼을 찾을 수 있습니다.

데이터베이스 인스턴스 생성 양식에는 GCP 프로젝트, Git ref(브랜치 또는 태그), 데이터베이스 버전 및 머신 타입의 필드가 있습니다. 제출 시 데이터베이스 인스턴스가 생성되고 데이터베이스 설정은 백그라운드 작업으로 대기열에 들어갑니다.

### 백그라운드 워커를 통한 데이터베이스 설정 {#database-setup-through-a-background-worker}

데이터베이스 인스턴스의 성공적인 생성은 다음 작업을 수행할 백그라운드 워커를 트리거합니다:

- 데이터베이스 사용자 생성
- 데이터베이스 스키마 생성
- 프로젝트의 CI/CD 변수에 데이터베이스 세부 정보 저장

### 데이터베이스에 연결 {#connect-to-the-database}

데이터베이스 인스턴스 설정이 완료되면 데이터베이스 연결 세부 정보를 프로젝트 변수로 사용할 수 있습니다. 이를 `Project :: Settings :: CI` 페이지를 통해 관리할 수 있으며 적절한 환경에서 실행되는 파이프라인에서 사용할 수 있게 됩니다.

### 데이터베이스 인스턴스 관리 {#managing-the-database-instance}

`Project :: Infrastructure :: Google Cloud :: Databases`의 인스턴스 목록은 Google Cloud 콘솔로 다시 연결됩니다. 인스턴스를 선택하여 세부 정보를 보고 인스턴스를 관리합니다.

## Cloud Seed에 기여 {#contribute-to-cloud-seed}

Cloud Seed에 기여할 수 있는 여러 가지 방법이 있습니다:

- Cloud Seed를 사용하고 [피드백을 공유하세요](https://gitlab.com/gitlab-org/incubation-engineering/five-minute-production/feedback/-/issues/new?template=general_feedback).
- Ruby on Rails 또는 Vue.js에 익숙하다면 개발자로서 GitLab에 기여하는 것을 고려하세요.
  - Cloud Seed의 대부분은 GitLab 코드베이스의 내부 모듈입니다.
- GitLab 파이프라인에 익숙하다면 [Cloud Seed Library](https://gitlab.com/gitlab-org/incubation-engineering/five-minute-production/library) 프로젝트에 기여하는 것을 고려하세요.
