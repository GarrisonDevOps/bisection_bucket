---
stage: Verify
group: Pipeline Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Atlassian Bamboo
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab의 프로젝트에 변경 사항을 푸시할 때 Atlassian Bamboo에서 빌드를 자동으로 트리거할 수 있습니다.

Bamboo는 웹후크와 커밋 데이터를 수용할 때 기존 빌드 시스템과 동일한 기능을 제공하지 않습니다. GitLab에서 통합을 구성하기 전에 Bamboo 빌드 플랜을 구성해야 합니다.

## Bamboo 구성 {#configure-bamboo}

1. Bamboo에서 빌드 계획으로 이동하여 **조치** > **Configure plan**을 선택합니다.
1. **트리거** 탭을 선택합니다.
1. **트리거 추가**를 선택합니다.
1. `GitLab trigger`와 같은 설명을 입력합니다.
1. **변경 사항이 커밋될 때 리포지토리가 빌드를 트리거합니다**를 선택합니다.
1. 하나 이상의 리포지토리에 대한 체크박스를 선택합니다.
1. GitLab IP 주소를 **Trigger IP addresses**에 입력합니다. 이 IP 주소들은 Bamboo 빌드를 트리거하도록 허용됩니다.
1. 트리거를 저장합니다.
1. 왼쪽 창에서 빌드 스테이지를 선택합니다. 여러 빌드 스테이지가 있는 경우 Git 체크아웃 작업이 포함된 마지막 스테이지를 선택합니다.
1. **기타** 탭을 선택합니다.
1. **Pattern Match Labeling** 아래에서 `${bamboo.repository.revision.number}`를 **라벨**에 입력합니다.
1. **저장**을 선택합니다.

Bamboo는 GitLab에서 트리거를 수락할 준비가 완료되었습니다. 다음으로 GitLab에서 Bamboo 통합을 설정합니다.

## GitLab 구성 {#configure-gitlab}

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Atlassian Bamboo**를 선택합니다.
1. **활성** 체크박스가 선택되어 있는지 확인합니다.
1. Bamboo 서버의 기본 URL을 입력합니다. 예를 들어, `https://bamboo.example.com`입니다.
1. 선택 사항. **SSL 검증 활성화** 체크박스를 선택 해제하여 [SSL 검증](_index.md#ssl-verification)을 비활성화합니다.
1. Bamboo 빌드 계획에서 [빌드 키](#identify-the-bamboo-build-plan-build-key)를 입력합니다.
1. 필요한 경우 빌드 계획을 트리거할 수 있는 액세스 권한이 있는 Bamboo 사용자의 사용자 이름과 암호를 입력합니다. 인증이 필요하지 않으면 이 필드를 비워 둡니다.
1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

### Bamboo 빌드 계획 빌드 키 식별 {#identify-the-bamboo-build-plan-build-key}

빌드 키는 일반적으로 프로젝트 키와 계획 키로 구성된 고유 식별자입니다. 빌드 키는 짧고 모두 대문자이며 대시(`-`)로 구분됩니다. 예를 들어 `PROJ-PLAN`입니다.

빌드 키는 Bamboo에서 계획을 볼 때 브라우저 URL에 포함됩니다. 예를 들어, `https://bamboo.example.com/browse/PROJ-PLAN`입니다.

## GitLab에서 Bamboo 빌드 상태 업데이트 {#update-bamboo-build-status-in-gitlab}

[커밋 상태 API](../../../api/commits.md#set-commit-pipeline-status)와 Bamboo 빌드 변수를 사용하는 스크립트를 사용하여 다음을 수행할 수 있습니다:

- 커밋을 빌드 상태로 업데이트합니다.
- Bamboo 빌드 계획 URL을 커밋의 `target_url`로 추가합니다.

예를 들어:

1. 범위를 `api`로 설정하여 [개인 액세스 토큰](../../profile/personal_access_tokens.md)을 생성합니다.
1. 토큰을 Bamboo의 `$GITLAB_TOKEN` 변수로 저장합니다.
1. 다음 스크립트를 Bamboo 계획의 작업에 대한 최종 작업으로 추가합니다:

   ```shell
   #!/bin/bash

   # Script to update CI status on GitLab.
   # Add this script as final inline script task in a Bamboo job.
   #
   # General documentation: https://docs.gitlab.com/user/project/integrations/bamboo/
   # Fix inspired from https://gitlab.com/gitlab-org/gitlab/-/issues/34744

   # Stop at first error
   set -e

   # Access token. Set this as a CI variable in Bamboo.
   #GITLAB_TOKEN=

   # Status
   cistatus="failed"
   if [ "${bamboo_buildFailed}" = "false" ]; then
     cistatus="success"
   fi

   repo_url="${bamboo_planRepository_repositoryUrl}"

   # Check if SSH or HTTPS is in use
   protocol=${repo_url::4}
   if [ "$protocol" == "git@" ]; then
     repo=${repo_url:${#protocol}};
     gitlab_url=${repo%%:*};
   else
     protocol="https://"
     repo=${repo_url:${#protocol}};
     gitlab_url=${repo%%/*};
   fi

   start=$((${#gitlab_url} + 1)) # +1 for the / (https) or : (ssh)
   end=$((${#repo} - $start -4)) # -4 for the .git
   repo=${repo:$start:$end}
   repo=$(echo "$repo" | sed "s/\//%2F/g")

   # Send request
   url="https://${gitlab_url}/api/v4/projects/${repo}/statuses/${bamboo_planRepository_revision}?state=${cistatus}&target_url=${bamboo_buildResultsUrl}"
   echo "Sending request to $url"
   curl --fail --request POST --header "PRIVATE-TOKEN: $GITLAB_TOKEN" "$url"
   ```

## 문제 해결 {#troubleshooting}

### 빌드가 트리거되지 않음 {#builds-not-triggered}

빌드가 트리거되지 않으면 Bamboo의 **Trigger IP addresses** 아래에 올바른 GitLab IP 주소를 입력했는지 확인합니다. 또한 통합 웹후크 로그에서 요청 실패를 확인합니다.

### GitLab UI에서 사용할 수 없는 Advanced Atlassian Bamboo 기능 {#advanced-atlassian-bamboo-features-not-available-in-gitlab-ui}

Advanced Atlassian Bamboo 기능은 GitLab과 호환되지 않습니다. 이러한 기능에는 GitLab UI에서 빌드 로그를 볼 수 있는 기능 등이 포함되어 있습니다.
