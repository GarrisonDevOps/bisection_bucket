---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 원격 리포지토리에서 GitLab으로 변경 사항을 가져오는 pull 미러를 생성하고 복사본을 최신 상태로 유지합니다.
title: 원격 리포지토리에서 pull하기
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab Premium 13.9로 이동했습니다.

{{< /history >}}

GitLab에서 호스팅되지 않은 경우에도 GitLab 인터페이스를 사용하여 리포지토리의 콘텐츠 및 활동을 검색할 수 있습니다. Pull [미러](_index.md)를 생성하여 업스트림 리포지토리에서 브랜치, 태그 및 커밋을 복사본으로 복사합니다.

[Push 미러](push.md)와 달리 pull 미러는 일정에 따라 업스트림(원격) 리포지토리에서 변경 사항을 검색합니다. 미러가 업스트림 리포지토리에서 분기되지 않도록 하려면 다운스트림 미러에 직접 커밋을 푸시하지 마세요. 대신 업스트림 리포지토리에 커밋을 푸시합니다. 원격 리포지토리의 변경 사항이 GitLab 리포지토리로 가져옵니다:

- 이전 pull 후 자동으로 30분 후입니다. 이를 비활성화할 수 없습니다.
- 관리자가 [미러를 강제 업데이트](_index.md#force-an-update)할 때입니다.
- [API 호출이 업데이트를 트리거](#trigger-an-update-by-using-the-api)할 때입니다.

UI 및 API 업데이트는 기본 [pull 미러링 간격](../../../../administration/instance_limits.md#pull-mirroring-interval)(5분)의 영향을 받습니다. 이 간격은 GitLab Self-Managed 인스턴스에서 구성할 수 있습니다.

기본적으로 다운스트림 pull 미러의 브랜치 또는 태그가 로컬 리포지토리에서 분기되면 GitLab이 브랜치 업데이트를 중지합니다. 이는 데이터 손실을 방지합니다. 업스트림 리포지토리에서 삭제된 브랜치 및 태그는 다운스트림 리포지토리에 반영되지 않습니다.

> [!note]
> 다운스트림 pull 미러 리포지토리에서 삭제되었지만 여전히 업스트림 리포지토리에 있는 항목은 다음 pull 시 복원됩니다. 예를 들어 미러된 리포지토리에서만 삭제된 브랜치는 다음 pull 후 다시 나타납니다.

## Pull 미러링 작동 방식 {#how-pull-mirroring-works}

GitLab 리포지토리를 pull 미러로 구성한 후:

1. GitLab이 리포지토리를 대기열에 추가합니다.
1. 분당 한 번씩 Sidekiq cron 작업이 다음을 기반으로 리포지토리 미러를 업데이트하도록 예약합니다:
   - Sidekiq 설정으로 결정되는 사용 가능한 용량입니다. GitLab.com의 경우 [GitLab.com Sidekiq 설정](../../../gitlab_com/_index.md#sidekiq)을 참조하세요.
   - 대기열에 있고 업데이트 예정인 미러가 몇 개인지입니다. 예정 여부는 리포지토리 미러가 마지막으로 업데이트된 시기와 업데이트가 재시도된 횟수에 따라 달라집니다.
1. Sidekiq이 업데이트를 처리할 수 있게 되면 미러가 업데이트됩니다. 업데이트 프로세스가:
   - 성공: 업데이트가 최소 30분 대기 후 다시 큐에 들어갑니다.
   - 실패: 업데이트는 나중에 다시 시도됩니다. 14번 실패 후 미러가 [하드 실패](#fix-hard-failures-when-mirroring)로 표시되고 더 이상 업데이트를 위해 큐에 들어가지 않습니다. 브랜치가 업스트림 대응 항목에서 분기되면 실패가 발생할 수 있습니다. 브랜치가 분기되지 않도록 하려면 미러를 생성할 때 [분기된 브랜치 덮어 쓰기](#overwrite-diverged-branches)를 구성합니다.

## Pull 미러링 구성 {#configure-pull-mirroring}

사전 요구 사항:

- 원격 리포지토리가 GitHub에 있고 [2단계 인증(2FA)이 구성](https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa)되어 있는 경우 `repo` 범위가 있는 [GitHub용 개인 액세스 토큰](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)을 생성합니다. 2FA가 활성화되면 이 개인 액세스 토큰이 GitHub 비밀번호로 작동합니다.
- [GitLab Silent Mode](../../../../administration/silent_mode/_index.md)가 활성화되지 않습니다.
- 업스트림 리포지토리와 GitLab 리포지토리가 동일한 객체 형식을 사용합니다. SHA-1과 SHA-256 리포지토리 간에 미러링할 수 없습니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **리포지토리 미러링**을 확장합니다.
1. **Git 리포지토리 URL**을 입력합니다.

   > [!note]
   > `gitlab` 리포지토리를 미러링하려면 `gitlab.com:gitlab-org/gitlab.git` 또는 `https://gitlab.com/gitlab-org/gitlab.git`를 사용합니다.

1. **미러 방향**에서 **Pull**을 선택합니다.
1. **인증 방법**에서 인증 방법을 선택합니다. 자세한 내용은 [미러용 인증 방법](_index.md#authentication-methods-for-mirrors)을 참조하세요.
1. 필요한 옵션을 선택합니다:
   - [**분기된 브랜치 덮어 쓰기**](#overwrite-diverged-branches)
   - [**미러링 업데이트를 위한 파이프라인 트리거**](#trigger-pipelines-for-mirror-updates)
   - **보호된 브랜치만 미러링**
1. 구성을 저장하려면 **리포지토리 미러링**을 선택합니다.

### 분기된 브랜치 덮어 쓰기 {#overwrite-diverged-branches}

{{< history >}}

- GitLab Premium 13.9로 이동했습니다.

{{< /history >}}

원격에서 분기된 경우에도 항상 로컬 브랜치를 원격 버전으로 업데이트하려면 미러를 생성할 때 **분기된 브랜치 덮어 쓰기**를 선택합니다.

> [!warning]
> 미러된 브랜치의 경우 이 옵션을 활성화하면 로컬 변경 사항이 손실됩니다.

### 미러링 업데이트를 위한 파이프라인 트리거 {#trigger-pipelines-for-mirror-updates}

{{< history >}}

- GitLab Premium 13.9로 이동했습니다.

{{< /history >}}

원격 리포지토리가 브랜치 또는 태그를 업데이트할 때 자동으로 파이프라인을 트리거하도록 미러를 구성할 수 있습니다. 이 기능을 활성화하기 전에:

- CI 러너가 원격 리포지토리 활동으로 인한 추가 부하를 처리할 수 있는지 확인합니다.
- 파이프라인이 pull 미러링을 설정한 사용자의 자격증명을 사용하기 때문에 보안 위험을 고려합니다. 예를 들어 악의적인 유지보수자는 다음을 수행할 수 있습니다:
  - 파이프라인이 실행될 때 저장된 CI/CD 변수 값을 가져오려고 시도하는 원격 리포지토리에 업데이트를 만듭니다.
  - [**리포지토리에 Git 푸시 요청 허용**](../../../../ci/jobs/ci_job_token.md#allow-git-push-requests-to-your-project-repository) 설정이 활성화되면 미러된 프로젝트에 커밋을 푸시합니다.

> [!warning]
> 신뢰할 수 있는 유지보수자가 있는 자신의 프로젝트 또는 프로젝트에 대해서만 이 기능을 활성화합니다.

## SSO 강제 적용을 통한 Pull 미러링 {#pull-mirroring-with-sso-enforcement}

그룹에 대해 [SSO 강제 적용](../../../group/saml_sso/_index.md#sso-enforcement)이 활성화되면 미러를 생성한 사용자는 활성 SSO 세션을 유지해야 하며, 그렇지 않으면 미러가 실패합니다.

SSO 세션 종속성 없이 미러링을 구성하려면 서비스 계정의 [프로젝트 액세스 토큰](../../settings/project_access_tokens.md), [그룹 액세스 토큰](../../../group/settings/group_access_tokens.md) 또는 [개인 액세스 토큰](../../../profile/personal_access_tokens.md)과 함께 [Pull 미러링 API](../../../../api/project_pull_mirroring.md)를 사용할 수 있습니다.

## API를 사용하여 업데이트 트리거 {#trigger-an-update-by-using-the-api}

{{< history >}}

- GitLab Premium 13.9로 이동했습니다.

{{< /history >}}

Pull 미러링은 폴링을 사용하여 업스트림에서 추가된 새 브랜치 및 커밋을 감지하며, 종종 몇 분 후에 감지합니다. [API 호출](../../../../api/project_pull_mirroring.md#start-the-pull-mirroring-process-for-a-project)을 사용하여 GitLab에 알릴 수 있지만 [pull 미러링 제한의 최소 간격](_index.md#force-an-update)은 여전히 적용됩니다.

자세한 내용은 [프로젝트를 위한 pull 미러링 프로세스 시작](../../../../api/project_pull_mirroring.md#start-the-pull-mirroring-process-for-a-project)을 참조하세요.

## 미러링 시 하드 실패 해결 {#fix-hard-failures-when-mirroring}

{{< history >}}

- GitLab Premium 13.9로 이동했습니다.

{{< /history >}}

14번 연속 재시도 실패 후 미러링 프로세스가 하드 실패로 표시되고 미러링 시도가 중지됩니다. 이 실패는 다음 중 하나에 표시됩니다:

- 프로젝트의 주 대시보드입니다.
- Pull 미러 설정 페이지입니다.

프로젝트 미러링을 재개하려면 [업데이트를 강제](_index.md#force-an-update)합니다.

오래된 네트워크 또는 서버 장애 후와 같이 여러 프로젝트가 이 문제의 영향을 받는 경우 [Rails 콘솔](../../../../administration/operations/rails_console.md)을 사용하여 이 명령으로 영향을 받는 모든 프로젝트를 식별하고 업데이트할 수 있습니다:

```ruby
Project.find_each do |p|
  if p.import_state && p.import_state.retry_count >= 14
    puts "Resetting mirroring operation for #{p.full_path}"
    p.import_state.reset_retry_count
    p.import_state.set_next_execution_to_now(prioritized: true)
    p.import_state.save!
  end
end
```

## 관련 항목 {#related-topics}

- 리포지토리 미러링을 위한 [문제 해결](troubleshooting.md)입니다.
- [Pull 미러링 간격](../../../../administration/instance_limits.md#pull-mirroring-interval)
- [프로젝트 pull 미러링 API](../../../../api/project_pull_mirroring.md#update-project-pull-mirroring-settings)
