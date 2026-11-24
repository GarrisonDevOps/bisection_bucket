---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 직접 전송 사용 시 마이그레이션되는 항목
description: "직접 전송 사용 시 포함되거나 제외되는 프로젝트 및 그룹 항목입니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

직접 전송 방법을 사용할 때 많은 항목이 마이그레이션되며, 일부는 제외됩니다.

> [!note]
> 사용자 정의 이모지를 사용하는 이모지 반응은 대상에 같은 이름의 사용자 정의 이모지가 있는 경우에만 마이그레이션됩니다. 대상에서 누락된 사용자 정의 이모지를 참조하는 반응은 건너뜁니다.

## 마이그레이션된 그룹 항목 {#migrated-group-items}

마이그레이션되는 그룹 항목은 대상에서 사용하는 GitLab의 버전에 따라 달라집니다. 특정 그룹 항목이 마이그레이션되는지 확인하려면:

1. [`groups/stage.rb`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/bulk_imports/groups/stage.rb) 파일을 모든 에디션에서 확인하고 [`groups/stage.rb`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/lib/ee/bulk_imports/groups/stage.rb) 파일을 엔터프라이즈 에디션의 대상 버전에서 확인합니다. 예를 들어, 버전 15.9의 경우:
   - <https://gitlab.com/gitlab-org/gitlab/-/blob/15-9-stable-ee/lib/bulk_imports/groups/stage.rb> (모든 에디션).
   - <https://gitlab.com/gitlab-org/gitlab/-/blob/15-9-stable-ee/ee/lib/ee/bulk_imports/groups/stage.rb> (엔터프라이즈 에디션).
1. [`group/import_export.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/import_export/group/import_export.yml) 파일을 대상의 버전에서 그룹에 대해 확인합니다. 예를 들어, 버전 15.9의 경우: <https://gitlab.com/gitlab-org/gitlab/-/blob/15-9-stable-ee/lib/gitlab/import_export/group/import_export.yml>.

다른 모든 그룹 항목은 마이그레이션되지 않습니다.

대상 GitLab 인스턴스로 마이그레이션되는 그룹 항목은 다음과 같습니다:

- 배지
- 보드
- 보드 목록
- 에픽
- 에픽 보드
- 에픽 보드 목록
- 그룹 레이블

  > [!note]
  > 그룹 레이블은 임포트 중에 연결된 레이블 우선순위를 유지할 수 없습니다. 대상 인스턴스로 관련 프로젝트를 마이그레이션한 후에 이러한 레이블의 우선순위를 수동으로 다시 설정해야 합니다.

- 그룹 마일스톤
- 반복
- 반복 주기
- [멤버](direct_transfer_migrations.md#user-membership-mapping)
- 네임스페이스 설정
- 릴리스 마일스톤
- 하위 그룹
- 업로드
- 위키

### 제외된 항목 {#excluded-items}

일부 그룹 항목은 다음 이유로 마이그레이션에서 제외됩니다:

- 민감한 정보를 포함할 수 있습니다:
  - CI/CD 변수
  - 배포 토큰
  - 웹후크
- 지원되지 않습니다:
  - 사용자 정의 필드
  - 반복 주기 설정
  - 보류 중인 멤버 초대
  - 푸시 규칙

또한 사용자 및 사용자가 생성한 [개인 액세스 토큰](../../profile/personal_access_tokens.md)은 마이그레이션에서 제외됩니다.

## 마이그레이션된 프로젝트 항목 {#migrated-project-items}

{{< history >}}

- [GitLab.com에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/339941) (GitLab 15.6).
- `bulk_import_projects` 기능 플래그 [제거됨](https://gitlab.com/gitlab-org/gitlab/-/issues/339941) (GitLab 15.10).
- API를 통한 프로젝트 마이그레이션 [추가됨](https://gitlab.com/gitlab-org/gitlab/-/issues/390515) (GitLab 15.11).
- GitLab 18.3에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/461326)입니다.

{{< /history >}}

[마이그레이션할 그룹을 선택](direct_transfer_migrations.md#select-the-groups-and-projects-to-import)할 때 프로젝트를 마이그레이션하기로 선택하면 프로젝트 항목이 프로젝트와 함께 마이그레이션됩니다.

마이그레이션되는 프로젝트 항목은 대상에서 사용하는 GitLab의 버전에 따라 달라집니다. 특정 프로젝트 항목이 마이그레이션되는지 확인하려면:

1. [`projects/stage.rb`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/bulk_imports/projects/stage.rb) 파일을 모든 에디션에서 확인하고 [`projects/stage.rb`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/lib/ee/bulk_imports/projects/stage.rb) 파일을 엔터프라이즈 에디션의 대상 버전에서 확인합니다. 예를 들어, 버전 15.9의 경우:
   - <https://gitlab.com/gitlab-org/gitlab/-/blob/15-9-stable-ee/lib/bulk_imports/projects/stage.rb> (모든 에디션).
   - <https://gitlab.com/gitlab-org/gitlab/-/blob/15-9-stable-ee/ee/lib/ee/bulk_imports/projects/stage.rb> (엔터프라이즈 에디션).
1. [`project/import_export.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/import_export/project/import_export.yml) 파일을 대상의 버전에서 프로젝트에 대해 확인합니다. 예를 들어, 버전 15.9의 경우: <https://gitlab.com/gitlab-org/gitlab/-/blob/15-9-stable-ee/lib/gitlab/import_export/project/import_export.yml>.

다른 모든 프로젝트 항목은 마이그레이션되지 않습니다.

그룹과 함께 프로젝트를 마이그레이션하지 않거나 프로젝트 마이그레이션을 다시 시도하려면 [API](../../../api/bulk_imports.md)를 사용하여 프로젝트 전용 마이그레이션을 시작할 수 있습니다.

대상 GitLab 인스턴스로 마이그레이션되는 프로젝트 항목은 다음과 같습니다:

- Auto DevOps
- 배지
- 브랜치 (보호된 브랜치 포함)

  > [!note]
  > 임포트된 브랜치는 대상 그룹의 [기본 브랜치 보호 설정](../../project/repository/branches/protected.md)을 준수합니다. 이러한 설정으로 인해 보호되지 않은 브랜치가 보호된 것으로 임포트될 수 있습니다.

- CI 파이프라인
  - 파이프라인 및 작업 레코드 (상태, 스테이지 및 타임스탬프 등)가 마이그레이션됩니다. 작업 로그 및 작업 아티팩트는 마이그레이션되지 않습니다.

  > [!warning]
  > 병합 요청의 임포트된 파이프라인은 소스 상태를 유지하며 대상 인스턴스에서 다시 실행하지 않고도 **파이프라인이 성공해야 함**과 [보안 정책 파이프라인 확인](../../application_security/policies/pipeline_execution_policies.md#security-policy-pipeline-check)을 충족할 수 있습니다. 병합하기 전에 가져온 병합 요청에서 새 파이프라인을 실행합니다.

- 커밋 댓글
- 디자인
- 외부 병합 요청
- 이슈
- 이슈 보드
- 레이블
- LFS 객체
- [멤버](direct_transfer_migrations.md#user-membership-mapping)
- 병합 요청
- 마일스톤
- 파이프라인 기록
- 파이프라인 일정
- 프로젝트
- 프로젝트 기능
- 푸시 규칙. 임포트 중에 [그룹 푸시 규칙](../../project/repository/push_rules.md#group-push-rules)이 프로젝트 푸시 규칙보다 우선합니다. 소스 인스턴스에 그룹 푸시 규칙이 있으면 프로젝트 푸시 규칙은 임포트되지 않습니다.
- 릴리스
- 릴리스 증거
- 리포지토리
- 설정
- 스니펫
- 업로드
- 취약성 보고서

  > [!note]
  > [GitLab 17.7에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/501466). 취약성 보고서는 상태 없이 마이그레이션됩니다. 자세한 내용은 [이슈 512859](https://gitlab.com/gitlab-org/gitlab/-/issues/512859)를 참조하세요. 취약성 보고서를 마이그레이션할 때 `ActiveRecord::RecordNotUnique` 오류는 [이슈 509904](https://gitlab.com/gitlab-org/gitlab/-/issues/509904)를 참조하세요.

- 위키

### 이슈 관련 항목 {#issue-related-items}

대상 GitLab 인스턴스로 마이그레이션되는 이슈 관련 프로젝트 항목은 다음과 같습니다:

- 이슈 댓글
- 이슈 반복
- 이슈 리소스 반복 이벤트
- 이슈 리소스 마일스톤 이벤트
- 이슈 리소스 상태 이벤트
- 병합 요청 URL 참조
- 시간 추적

### 병합 요청 관련 항목 {#merge-request-related-items}

대상 GitLab 인스턴스로 마이그레이션되는 병합 요청 관련 프로젝트 항목은 다음과 같습니다:

- 이슈 URL 참조
- 병합 요청 승인자
- 병합 요청 댓글
- 병합 요청 리소스 마일스톤 이벤트
- 병합 요청 리소스 상태 이벤트
- 병합 요청 검토자
- 여러 병합 요청 담당자
- 시간 추적

### 설정 관련 항목 {#setting-related-items}

대상 GitLab 인스턴스로 마이그레이션되는 설정 관련 프로젝트 항목은 다음과 같습니다:

- 아바타
- 컨테이너 만료 정책
- 프로젝트 속성
- 서비스 데스크

### 제외된 항목 {#excluded-items-1}

일부 프로젝트 항목은 다음 이유로 마이그레이션에서 제외됩니다:

- 민감한 정보를 포함할 수 있습니다:
  - CI/CD 작업 로그
  - CI/CD 변수
  - 컨테이너 레지스트리 이미지
  - 배포 키
  - 배포 토큰
  - 암호화된 토큰
  - 작업 아티팩트
  - 파이프라인 일정 변수
  - 파이프라인 트리거
  - 웹후크
- 지원되지 않습니다:
  - 에이전트
  - [하위 CI/CD 파이프라인](https://gitlab.com/gitlab-org/gitlab/-/issues/571159)
  - 컨테이너 레지스트리
  - 사용자 정의 필드
  - 환경
  - 기능 플래그
  - 인프라 레지스트리
  - GitLab Self-Managed에서 GitLab.com 또는 GitLab Dedicated로 마이그레이션할 때 브랜치 보호 규칙의 인스턴스 관리자
  - 연결된 이슈
  - 병합 요청 승인 규칙
  - 병합 요청 종속성
  - 패키지 레지스트리
  - 페이지 도메인
  - 보류 중인 멤버 초대
  - 원격 미러
  - 위키 댓글

    > [!note]
    > 프로젝트 설정과 관련된 승인 규칙이 임포트됩니다.

- 복구할 수 있는 데이터가 없습니다:
  - diff 또는 소스 정보가 없는 병합 요청 (자세한 내용은 [이슈 537943](https://gitlab.com/gitlab-org/gitlab/-/issues/537943)을 참조하세요)

또한 사용자 및 사용자가 생성한 [개인 액세스 토큰](../../profile/personal_access_tokens.md)은 마이그레이션에서 제외됩니다.
