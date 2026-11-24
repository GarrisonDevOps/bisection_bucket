---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab을 GitGuardian과 통합하여 정책 위반 및 보안 문제에 대한 경고를 악용되기 전에 받으세요.
title: GitGuardian
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/435706) GitLab 16.9 [기능 플래그 포함](../../../administration/feature_flags/_index.md) `git_guardian_integration`으로 명명됨. 기본적으로 활성화됩니다. GitLab.com에서 비활성화됨.
- [GitLab.com에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/438695#note_2226917025) GitLab 17.7에서.
- [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/176391) GitLab 17.8에서. 기능 플래그 `git_guardian_integration`이 제거되었습니다.
- `api_url` 매개변수 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/599742) GitLab 19.1에서.

{{< /history >}}

[GitGuardian](https://www.gitguardian.com/)은 소스 코드 리포지토리에서 API 키, 비밀번호 및 토큰과 같은 하드코딩된 자격 증명을 찾는 시크릿 검색 서비스입니다. 이 통합을 활성화하면 GitLab에서 각 푸시를 GitGuardian에 스캔을 위해 보냅니다. GitGuardian에서 시크릿을 감지하면 GitLab에서 푸시를 차단합니다.

GitGuardian 정책을 기반으로 커밋을 거부하도록 GitLab을 구성할 수 있습니다.

GitGuardian 통합을 설정하려면:

1. [GitGuardian API 토큰 생성](#create-a-gitguardian-api-token).
1. [프로젝트에 대한 GitGuardian 통합 설정](#set-up-the-gitguardian-integration-for-your-project).

## GitGuardian API 토큰 생성 {#create-a-gitguardian-api-token}

사전 요구 사항:

- GitGuardian 계정이 있어야 합니다.

API 토큰을 생성하려면:

1. GitGuardian 계정에 로그인합니다.
1. 사이드바에서 **API** 섹션으로 이동합니다.
1. API 섹션 사이드바에서 **개인 액세스 토큰** 페이지로 이동합니다.
1. **토큰 생성**을 선택합니다. 토큰 생성 대화 상자가 열립니다.
1. 토큰 정보를 제공합니다:
   - API 토큰에 의미 있는 이름을 지정하여 목적을 식별합니다. 예를 들어, `GitLab integration token`입니다.
   - 적절한 만료를 선택합니다.
   - **스캔 범위** 확인란을 선택합니다. 통합에 필요한 유일한 것입니다.
1. **토큰 생성**을 선택합니다.
1. 토큰을 생성한 후 클립보드에 복사합니다. 이 토큰은 민감한 정보이므로 안전하게 유지합니다.

이제 통합에 사용할 수 있는 GitGuardian API 토큰을 성공적으로 생성했습니다.

## 프로젝트에 대한 GitGuardian 통합 설정 {#set-up-the-gitguardian-integration-for-your-project}

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

API 토큰을 생성하고 복사한 후 GitLab을 구성하여 커밋을 거부합니다:

프로젝트에 대한 통합을 활성화하려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **GitGuardian**을 선택합니다.
1. **통합 활성화**에서 **활성** 확인란을 선택합니다.
1. 선택 사항. **API 엔드포인트** 텍스트 상자에 GitGuardian 인스턴스의 기본 URL을 입력합니다:
   - GitGuardian EU SaaS의 경우 `https://api.eu1.gitguardian.com`을 입력합니다.
   - 자체 호스팅 GitGuardian의 경우 인스턴스 URL을 입력합니다(예: `https://gitguardian.example.com`).

   이를 비워두면 GitLab에서 기본 US SaaS 엔드포인트( `https://api.gitguardian.com`)를 사용합니다.

1. **API 토큰**에서 [GitGuardian에서 토큰 값 붙여넣기](#create-a-gitguardian-api-token).
1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

이제 GitLab은 GitGuardian 정책을 기반으로 커밋을 거부할 준비가 되었습니다.

## 시크릿 검색 건너뛰기 {#skip-secret-detection}

{{< history >}}

- GitLab 17.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/152064)되었습니다.

{{< /history >}}

필요한 경우 GitGuardian 시크릿 검색을 건너뛸 수 있습니다. 푸시에서 모든 커밋에 대한 시크릿 검색을 건너뛰는 옵션은 [기본 시크릿 검색](../../application_security/secret_detection/secret_push_protection/_index.md#skip-secret-push-protection)의 옵션과 동일합니다. 다음 중 하나를 선택합니다.

- `[skip secret push protection]`을 커밋 메시지 중 하나에 추가합니다.
- `secret_push_protection.skip_all` [푸시 옵션](../../../topics/git/commit.md#push-options-for-gitguardian-integration)을 사용합니다.

## 알려진 이슈 {#known-issues}

- 푸시가 지연되거나 시간이 초과될 수 있습니다. GitGuardian 통합 사용:
  - 푸시가 제3자에게 전송됩니다.
  - GitLab에서는 GitGuardian과의 연결 또는 GitGuardian 프로세스를 제어할 수 없습니다.
- [GitGuardian API 제한](https://api.gitguardian.com/docs#operation/multiple_scan)으로 인해 통합에서 1 MB를 초과하는 파일을 무시합니다. 스캔되지 않습니다.
- 푸시된 파일의 이름이 256자를 초과하면 푸시가 실패합니다.
- 자세한 내용은 [GitGuardian API 설명서](https://api.gitguardian.com/docs#operation/multiple_scan)를 참조하세요.

아래의 문제 해결 단계는 이러한 문제 중 일부를 완화하는 방법을 보여줍니다.

## 문제 해결 {#troubleshooting}

GitGuardian 통합으로 작업할 때 다음 문제가 발생할 수 있습니다.

### `500` HTTP 오류 {#500-http-errors}

HTTP `500` 오류가 발생할 수 있습니다.

이 문제는 변경된 파일이 많은 커밋에 대해 요청이 시간 초과될 때 발생합니다.

커밋에서 50개를 초과하는 파일을 변경할 때 이 문제가 발생하면:

1. 변경 사항을 더 작은 커밋으로 분할합니다.
1. 더 작은 커밋을 하나씩 푸시합니다.

### 오류: `Filename: ensure this value has at most 256 characters` {#error-filename-ensure-this-value-has-at-most-256-characters}

HTTP `400` 오류 상태 `Filename: ensure this value has at most 256 characters`이 표시될 수 있습니다.

이 문제는 해당 커밋에서 푸시하는 변경된 파일 중 일부의 파일명(경로가 아님)이 256자보다 긴 경우 발생합니다.

해결 방법은 가능한 경우 파일명을 단축하는 것입니다. 예를 들어 파일명이 프레임워크에서 자동으로 생성되었기 때문에 단축할 수 없는 경우 통합을 비활성화하고 다시 푸시합니다. 필요한 경우 나중에 통합을 다시 활성화하는 것을 잊지 마세요.
