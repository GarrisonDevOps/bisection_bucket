---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
gitlab_dedicated: yes
description: "Git HTTP, Git LFS 및 Git SSH 작업에서 속도 제한을 구성합니다."
title: Git 작업 속도 제한
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

클론, 페치, 푸시와 같은 일반적인 Git 작업은 짧은 시간에 많은 요청을 생성할 수 있습니다. Git HTTP, Git LFS 및 Git SSH 작업의 속도 제한은 GitLab 인스턴스의 보안과 안정성을 보호합니다. 이러한 각 제한은 [일반 사용자 및 IP 속도 제한](../administration/settings/user_and_ip_rate_limits.md)과 다르게 작동합니다. 각 섹션에서 자세히 설명합니다.

## Git HTTP {#git-http}

{{< history >}}

- GitLab 17.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/147112)되었습니다.

{{< /history >}}

리포지토리에서 Git HTTP를 사용하면 일반적인 Git 작업이 많은 Git HTTP 요청을 생성할 수 있습니다. GitLab은 인증된 Git HTTP 요청과 인증되지 않은 Git HTTP 요청 모두에 대해 속도 제한을 적용하여 웹 애플리케이션의 보안과 안정성을 개선할 수 있습니다.

> [!note]
> [일반 사용자 및 IP 속도 제한](../administration/settings/user_and_ip_rate_limits.md)은 Git HTTP 요청에 적용되지 않습니다.

### GitLab.com의 Git HTTP {#git-http-on-gitlabcom}

GitLab.com에서 Git HTTP 요청은 [Git HTTPS 요청 속도 제한](../user/gitlab_com/rate_limits.md#current-rate-limits)의 대상입니다.

### 인증되지 않은 Git HTTP 속도 제한 구성 {#configure-unauthenticated-git-http-rate-limits}

GitLab은 기본적으로 인증되지 않은 Git HTTP 요청에 대한 속도 제한을 사용 안 함으로 설정합니다.

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

인증 매개변수가 포함되지 않은 Git HTTP 요청에 속도 제한을 적용하려면 다음 제한을 활성화하고 구성합니다:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **Git HTTP 속도 제한**을 펼칩니다.
1. **인증되지 않은 Git HTTP 요청 속도 제한 활성화**를 선택합니다.
1. **사용자당 기간당 최대 인증되지 않은 Git HTTP 요청**에 대한 값을 입력합니다.
1. **인증되지 않은 Git HTTP 속도 제한 기간(초)**에 대한 값을 입력합니다.
1. **변경 사항 저장**을 선택합니다.

### 인증된 Git HTTP 속도 제한 구성 {#configure-authenticated-git-http-rate-limits}

{{< history >}}

- 인증된 Git HTTP 속도 제한이 GitLab 18.1에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/191552)되었으며, [기능 플래그](../administration/feature_flags/_index.md) `git_authenticated_http_limit`의 이름으로 표시됩니다. 기본적으로 비활성화되었습니다.
- GitLab 18.3에서 [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/543768)되었습니다.
- GitLab 18.4에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/561577)합니다. 기능 플래그 `git_authenticated_http_limit`가 제거되었습니다.

{{< /history >}}

GitLab은 기본적으로 인증된 Git HTTP 요청에 대한 속도 제한을 사용 안 함으로 설정합니다.

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

인증 매개변수가 포함된 Git HTTP 요청에 속도 제한을 적용하려면 다음 제한을 활성화하고 구성합니다:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **Git HTTP 속도 제한**을 펼칩니다.
1. **인증된 Git HTTP 요청 속도 제한 활성화**를 선택합니다.
1. **사용자당 기간당 최대 인증된 Git HTTP 요청**에 대한 값을 입력합니다.
1. **인증된 Git HTTP 속도 제한 기간(초)**에 대한 값을 입력합니다.
1. **변경 사항 저장**을 선택합니다.

필요한 경우 [특정 사용자가 인증된 요청 속도 제한을 무시하도록 허용](../administration/settings/user_and_ip_rate_limits.md#allow-specific-users-to-bypass-authenticated-request-rate-limiting)할 수 있습니다.

## Git LFS {#git-lfs}

[Git Large File Storage(LFS)](../topics/git/lfs/_index.md)는 대용량 파일을 처리하기 위한 Git 확장 프로그램입니다. Git LFS를 사용하는 리포지토리는 많은 수의 LFS 요청을 생성할 수 있습니다. [일반 사용자 및 IP 속도 제한](../administration/settings/user_and_ip_rate_limits.md)을 적용할 수 있지만, 일반 설정을 무시하여 Git LFS 요청에 추가 제한을 적용할 수도 있습니다. 이러한 무시 설정은 웹 애플리케이션의 보안과 안정성을 개선할 수 있습니다.

### GitLab.com의 Git LFS {#git-lfs-on-gitlabcom}

GitLab.com에서 Git LFS 요청은 [인증된 웹 요청 속도 제한](../user/gitlab_com/rate_limits.md#current-rate-limits)의 대상입니다. 이러한 제한은 사용자당 분당 1000개 요청으로 설정됩니다.

업로드되거나 다운로드되는 각 Git LFS 객체는 이 제한에 대해 계산되는 HTTP 요청을 생성합니다.

> [!note]
> 여러 대용량 파일이 있는 프로젝트는 HTTP 속도 제한 오류가 발생할 수 있습니다. 이 오류는 CI/CD 파이프라인과 같은 자동화된 환경에서 단일 IP 주소에서 수행할 때 클론 또는 풀 중에 발생합니다.

### Git LFS 속도 제한 구성 {#configure-git-lfs-rate-limits}

Git LFS 속도 제한은 GitLab Self-Managed 인스턴스에서 기본적으로 사용 안 함으로 설정됩니다. 관리자는 Git LFS 트래픽에 대해 특별히 전용 속도 제한을 구성할 수 있습니다. 활성화되면 이러한 전용 LFS 속도 제한은 기본 [사용자 및 IP 속도 제한](../administration/settings/user_and_ip_rate_limits.md)을 무시합니다.

전제 조건:

- 인스턴스의 관리자여야 합니다.

Git LFS 속도 제한을 구성하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **Git LFS 속도 제한**을 펼칩니다.
1. **인증된 Git LFS 요청 속도 제한 활성화**를 선택합니다.
1. **사용자당 기간당 최대 인증된 Git LFS 요청**에 대한 값을 입력합니다.
1. **인증된 Git LFS 속도 제한 기간(초)**에 대한 값을 입력합니다.
1. **변경 사항 저장**을 선택합니다.

## Git SSH 작업 {#git-ssh-operations}

GitLab은 사용자 계정 및 프로젝트별로 SSH를 사용하는 Git 작업에 속도 제한을 적용합니다. 사용자가 속도 제한을 초과하면 GitLab은 해당 프로젝트에 대해 해당 사용자의 추가 연결 요청을 거부합니다.

속도 제한은 Git 명령([배관](https://git-scm.com/book/en/v2/Git-Internals-Plumbing-and-Porcelain)) 수준에서 적용됩니다. 기본적으로 각 명령의 속도 제한은 분당 600개입니다. 예를 들어:

- `git push`의 속도 제한은 분당 600개입니다.
- `git pull`의 속도 제한은 분당 600개입니다.

`git-upload-pack`, `git pull` 및 `git clone` 명령은 명령을 공유하기 때문에 속도 제한을 공유합니다.

> [!note]
> [일반 사용자 및 IP 속도 제한](../administration/settings/user_and_ip_rate_limits.md)은 Git SSH 작업에 적용되지 않습니다. SSH 트래픽은 내부 API를 통해 GitLab에 도달하므로 이 제한에만 계산됩니다.

### GitLab.com의 Git SSH 작업 {#git-ssh-operations-on-gitlabcom}

GitLab.com에서 Git SSH 작업은 분당 600개 작업의 기본 속도 제한을 사용합니다. 이 제한을 변경할 수 없습니다.

### GitLab Shell 작업 제한 구성 {#configure-the-gitlab-shell-operation-limit}

`Git operations using SSH`은 기본적으로 활성화됩니다. 기본값은 사용자당 분당 600입니다.

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **Git SSH 작업 속도 제한**을 펼칩니다.
1. **분당 최대 Git 작업 수**에 대한 값을 입력합니다.
   - 속도 제한을 비활성화하려면 `0`으로 설정합니다.
1. **변경 사항 저장**을 선택합니다.

## 관련 항목 {#related-topics}

- [속도 제한](_index.md)
- [사용자 및 IP 속도 제한](../administration/settings/user_and_ip_rate_limits.md)
- [구성 불가능한 속도 제한](non_configurable.md)
