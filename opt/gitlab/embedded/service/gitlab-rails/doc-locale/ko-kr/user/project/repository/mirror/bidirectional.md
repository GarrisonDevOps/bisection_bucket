---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 두 Git 리포지토리 간의 변경 사항을 푸시하고 풀하기 위해 양방향 미러를 생성합니다.
title: 양방향 미러링
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- 13.9에서 GitLab Premium으로 이동했습니다.

{{< /history >}}

> [!warning]
> 양방향 미러링이 충돌을 일으킬 수 있습니다.

양방향 [미러링](_index.md)은 두 리포지토리가 서로 풀(pull)하고 푸시(push)하도록 구성합니다. 리포지토리 중 하나도 오류 없이 업데이트할 수 있다는 보장이 없습니다.

## 양방향 미러링의 충돌 감소 {#reduce-conflicts-in-bidirectional-mirroring}

양방향 미러링을 구성하려면 리포지토리를 충돌에 대비하세요. 충돌을 줄이도록 구성하고 발생했을 때 충돌을 해결하는 방법을 알아봅시다:

- [보호된 브랜치만 미러링](_index.md#mirror-only-protected-branches)합니다. 미러링된 커밋을 원격 저장소에서 다시 쓰면 충돌이 발생하고 미러링이 실패합니다.
- [브랜치를 보호](../branches/protected.md)하여 두 원격 저장소에서 미러링하고 싶은 브랜치를 보호하여 기록 다시 쓰기로 인한 충돌을 방지합니다.
- [푸시 이벤트 웹후크](../../integrations/webhook_events.md#push-events)로 미러링 지연을 줄입니다. 양방향 미러링은 같은 브랜치에 가까운 시간에 작성된 커밋이 충돌을 일으키는 경쟁 상태를 만듭니다. 푸시 이벤트 웹후크는 경쟁 상태를 완화하는 데 도움이 될 수 있습니다. GitLab에서 푸시 미러링은 보호된 브랜치만 푸시 미러링할 때 분당 한 번으로 속도 제한됩니다.
- [pre-receive 훅을 사용하여](#prevent-conflicts-by-using-a-pre-receive-hook) 충돌을 방지합니다.

## GitLab으로 즉시 풀(pull)을 트리거하도록 웹후크 구성 {#configure-a-webhook-to-trigger-an-immediate-pull-to-gitlab}

[푸시 이벤트 웹후크](../../integrations/webhook_events.md#push-events)는 다운스트림 인스턴스에서 변경 사항을 더 자주 동기화하여 경쟁 상태를 줄이는 데 도움이 됩니다.

사전 요구 사항:

- 업스트림 GitLab 인스턴스에서 [푸시](push.md#set-up-a-push-mirror-to-another-gitlab-instance-with-2fa-activated) 및 [풀](pull.md) 미러를 구성했습니다.

다운스트림 인스턴스에서 웹후크를 생성하려면:

1. [개인 액세스 토큰](../../../profile/personal_access_tokens.md)을 `API` 범위로 생성합니다.
1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **웹후크**를 선택합니다.
1. 웹후크 **URL**을 추가합니다. 이 경우 [풀 미러 API](../../../../api/project_pull_mirroring.md#start-the-pull-mirroring-process-for-a-project) 요청을 사용하여 리포지토리 업데이트 후 즉시 풀을 트리거합니다:

   ```plaintext
   https://gitlab.example.com/api/v4/projects/:id/mirror/pull?private_token=<your_access_token>
   ```

1. [토큰 마스킹](../../integrations/webhooks.md#mask-sensitive-portions-of-webhook-urls)합니다.
1. **푸시 이벤트**를 선택합니다.
1. **웹후크 추가**를 선택합니다.

통합을 테스트하려면 **테스트**를 선택하고 GitLab에서 오류 메시지를 반환하지 않는지 확인합니다.

## pre-receive 훅을 사용하여 충돌 방지 {#prevent-conflicts-by-using-a-pre-receive-hook}

> [!warning]
> 이 솔루션은 Git 푸시 작업의 성능에 부정적인 영향을 미칩니다. 업스트림 Git 리포지토리로 프록시되기 때문입니다.

이 구성에서는 한 Git 리포지토리가 신뢰할 수 있는 업스트림으로 작동하고 다른 하나는 다운스트림으로 작동합니다. 이 서버 측 `pre-receive` 훅은 먼저 커밋을 업스트림 리포지토리로 푸시한 후에만 푸시를 허용합니다. 이 훅을 다운스트림 리포지토리에 설치합니다.

예를 들어:

```shell
#!/usr/bin/env bash

# --- Assume only one push mirror target
# Push mirroring remotes are named `remote_mirror_<id>`.
# This line finds the first remote and uses that.
TARGET_REPO=$(git remote | grep -m 1 remote_mirror)

proxy_push()
{
  # --- Arguments
  OLDREV=$(git rev-parse $1)
  NEWREV=$(git rev-parse $2)
  REFNAME="$3"

  # --- Pattern of branches to proxy pushes
  allowlist=$(expr "$branch" : "\(master\)")

  case "$refname" in
    refs/heads/*)
      branch=$(expr "$refname" : "refs/heads/\(.*\)")

      if [ "$allowlist" = "$branch" ]; then
        # handle https://git-scm.com/docs/git-receive-pack#_quarantine_environment
        unset GIT_QUARANTINE_PATH
        error="$(git push --quiet $TARGET_REPO $NEWREV:$REFNAME 2>&1)"
        fail=$?

        if [ "$fail" != "0" ]; then
          echo >&2 ""
          echo >&2 " Error: updates were rejected by upstream server"
          echo >&2 "   This is usually caused by another repository pushing changes"
          echo >&2 "   to the same ref. You may want to first integrate remote changes"
          echo >&2 ""
          return
        fi
      fi
      ;;
  esac
}

# Allow dual mode: run from the command line just like the update hook, or
# if no arguments are given, then run as a hook script:
if [ -n "$1" -a -n "$2" -a -n "$3" ]; then
  # Output to the terminal in command line mode. If someone wanted to
  # resend an email, they could redirect the output to sendmail themselves
  PAGER= proxy_push $2 $3 $1
else
  # Push is proxied upstream one ref at a time. It is possible for some refs
  # to succeed, and others to fail. This results in a failed push.
  while read oldrev newrev refname
  do
    proxy_push $oldrev $newrev $refname
  done
fi
```

이 샘플에는 몇 가지 제한 사항이 있습니다:

- 수정하지 않으면 사용 사례에 대해 작동하지 않을 수 있습니다:
  - 미러에 대한 다양한 인증 메커니즘 유형을 고려하지 않습니다.
  - 강제 업데이트(기록 다시 쓰기)와 함께 작동하지 않습니다.
  - `allowlist` 패턴과 일치하는 브랜치만 프록시 푸시됩니다.
- 스크립트는 `$TARGET_REPO`의 업데이트가 ref 업데이트로 인식되고 Git이 이에 대한 경고를 표시하기 때문에 Git 훅 격리 환경을 우회합니다.

## 관련 항목 {#related-topics}

- 리포지토리 미러링을 위한 [문제 해결](troubleshooting.md)입니다.
- [서버 훅 구성](../../../../administration/server_hooks.md)
