---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 일반적인 명령어와 워크플로우입니다.
title: "변경 사항 스테이징, 커밋 및 푸시"
---

리포지토리의 파일을 변경하면 Git은 체크 아웃된 브랜치의 최신 버전에 대해 변경 사항을 추적합니다. Git 명령어를 사용하여 브랜치에 변경 사항을 검토 및 커밋하고 작업을 GitLab으로 푸시할 수 있습니다.

## 로컬 변경 사항 추가 및 커밋 {#add-and-commit-local-changes}

브랜치에 변경 사항을 작성할 준비가 되면 커밋할 수 있습니다. 커밋에는 변경 사항에 대한 정보를 기록하는 주석이 포함되어 있으며 일반적으로 브랜치의 새로운 끝이 됩니다.

Git은 커밋에서 이동, 변경 또는 삭제한 파일을 자동으로 포함하지 않습니다. 이는 임시 디렉토리와 같은 변경 사항이나 파일을 실수로 포함하는 것을 방지합니다. 커밋에 변경 사항을 포함하려면 `git add`을(를) 사용하여 스테이징합니다.

변경 사항을 스테이징하고 커밋하려면:

1. 리포지토리에서 추가하려는 각 파일 또는 디렉토리에 대해 다음을 실행합니다:

   ```shell
   git add <file name or path>
   ```

   현재 작업 디렉토리의 모든 파일을 스테이징하려면 다음을 실행합니다:

   ```shell
   git add .
   ```

1. 파일이 스테이징에 추가되었는지 확인합니다:

   ```shell
   git status
   ```

   파일이 녹색으로 표시됩니다.
1. 스테이징된 파일을 커밋하려면:

   ```shell
   git commit -m "<comment that describes the changes>"
   ```

변경 사항이 브랜치로 커밋됩니다.

### 좋은 커밋 메시지 작성 {#write-a-good-commit-message}

Chris Beams가 게시한 [How to Write a Git Commit Message](https://cbea.ms/git-commit/) 지침은 좋은 커밋 메시지를 작성하는 데 도움이 됩니다:

- 커밋 제목과 본문은 빈 줄로 구분해야 합니다.
- 커밋 제목은 대문자로 시작해야 합니다.
- 커밋 제목은 72자를 초과할 수 없습니다.
- 커밋 제목은 마침표로 끝나면 안 됩니다.
- 커밋 본문은 줄당 72자를 초과할 수 없습니다.
- 커밋 제목 또는 본문에 이모지를 포함하면 안 됩니다.
- 3개 이상의 파일에서 30줄 이상을 변경하는 커밋은 커밋 본문에 이러한 변경 사항을 설명해야 합니다.
- 짧은 참조 대신 이슈, 마일스톤 및 머지 리퀘스트의 전체 URL을 사용합니다. 이는 GitLab 외부에서 일반 텍스트로 표시되기 때문입니다.
- 머지 리퀘스트는 10개 이상의 커밋 메시지를 포함하면 안 됩니다.
- 커밋 제목은 최소 3개의 단어를 포함해야 합니다.

## 모든 변경 사항 커밋 {#commit-all-changes}

한 번의 명령어로 모든 변경 사항을 스테이징하고 커밋할 수 있습니다:

```shell
git commit -a -m "<comment that describes the changes>"
```

커밋이 원격 리포지토리에 기록하고 싶지 않은 파일을 포함하지 않도록 주의하세요. 원칙적으로 변경 사항을 커밋하기 전에 항상 로컬 리포지토리의 상태를 확인합니다.

## GitLab에 변경 사항 전송 {#send-changes-to-gitlab}

모든 로컬 변경 사항을 원격 리포지토리로 푸시하려면:

```shell
git push <remote> <name-of-branch>
```

예를 들어 로컬 커밋을 `main` 브랜치의 `origin` 원격으로 푸시하려면:

```shell
git push origin main
```

때때로 Git은 리포지토리로 푸시할 수 없습니다. 대신 [강제 업데이트](git_rebase.md#force-push-to-a-remote-branch)해야 합니다.

## 푸시 옵션 {#push-options}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

브랜치로 변경 사항을 푸시할 때 클라이언트 측 [Git 푸시 옵션](https://git-scm.com/docs/git-push#Documentation/git-push.txt--oltoptiongt)을 사용할 수 있습니다. Git 2.10 이상에서 Git 푸시 옵션을 사용하여:

- [CI 작업 건너뛰기](#push-options-for-gitlab-cicd)
- [머지 리퀘스트로 푸시](#push-options-for-merge-requests)

Git 2.18 이상에서는 긴 형식(`--push-option`) 또는 더 짧은 `-o`을(를) 사용할 수 있습니다:

```shell
git push -o <push_option>
```

Git 2.10~2.17에서는 긴 형식을 사용해야 합니다:

```shell
git push --push-option=<push_option>
```

서버 측 제어 및 모범 사례 적용은 [푸시 규칙](../../user/project/repository/push_rules.md) 및 [서버 훅](../../administration/server_hooks.md)을(를) 참조합니다.

### GitLab CI/CD의 푸시 옵션 {#push-options-for-gitlab-cicd}

푸시 옵션을 사용하여 CI/CD 파이프라인을 건너뛰거나 CI/CD 변수를 전달할 수 있습니다.

> [!note]
> 푸시 옵션은 머지 리퀘스트 파이프라인에서 사용할 수 없습니다. 자세한 내용은 [이슈 373212](https://gitlab.com/gitlab-org/gitlab/-/issues/373212)를 참조합니다.

| 푸시 옵션                    | 설명 | 예제 |
|--------------------------------|-------------|---------|
| `ci.input=<name>=<value>`      | 파이프라인에 입력 매개변수를 전달합니다. | `git push -o ci.input='stage=test' -o ci.input='security_scan=false'`. 배열 입력: `git push -o ci.input='my_array=["string", "double", "quotes"]'` |
| `ci.skip`                      | 이 푸시의 파이프라인을 건너뜁니다. 브랜치 파이프라인에만 영향을 주며, [머지 리퀘스트 파이프라인](../../ci/pipelines/merge_request_pipelines.md)에는 영향을 주지 않습니다. Jenkins와 같은 CI/CD 통합은 건너뛰지 않습니다. | `git push -o ci.skip` |
| `ci.no_pipeline`               | 최신 푸시에 대한 파이프라인 생성을 방지합니다.   | `git push -o ci.no_pipeline` |
| `ci.variable="<name>=<value>"` | 파이프라인에 [CI/CD 변수](../../ci/variables/_index.md)를 설정합니다. 브랜치 파이프라인에만 영향을 주며, [머지 리퀘스트 파이프라인](../../ci/pipelines/merge_request_pipelines.md)에는 영향을 주지 않습니다. | `git push -o ci.variable="MAX_RETRIES=10" -o ci.variable="MAX_TIME=600"` |

### 통합을 위한 푸시 옵션 {#push-options-for-integrations}

푸시 옵션을 사용하여 통합 CI/CD 파이프라인을 건너뛸 수 있습니다.

| 푸시 옵션                    | 설명 | 예제 |
|--------------------------------|-------------|---------|
| `integrations.skip_ci`         | Atlassian Bamboo, Buildkite, Drone, Jenkins, JetBrains TeamCity와 같은 CI/CD 통합에 대한 푸시 이벤트를 건너뜁니다. | `git push -o integrations.skip_ci` |

### 머지 리퀘스트의 푸시 옵션 {#push-options-for-merge-requests}

Git 푸시 옵션은 변경 사항을 푸시하는 동안 머지 리퀘스트에 대한 작업을 수행할 수 있습니다:

| 푸시 옵션                                  | 설명 |
|----------------------------------------------|-------------|
| `merge_request.create`                       | 푸시된 브랜치에 대한 새 머지 리퀘스트를 생성합니다. 기본 브랜치에서 푸시할 때 `merge_request.target` 옵션을 사용하여 대상 브랜치를 지정하여 머지 리퀘스트를 생성해야 합니다. |
| `merge_request.target=<branch_name>`         | 머지 리퀘스트의 대상을 특정 브랜치로 설정합니다. 예: `git push -o merge_request.target=branch_name`. 기본 브랜치에서 머지 리퀘스트를 생성할 때 필수입니다. |
| `merge_request.target_project=<project>`     | 머지 리퀘스트의 대상을 특정 업스트림 프로젝트로 설정합니다. 예: `git push -o merge_request.target_project=path/to/project`. |
| `merge_request.merge_when_pipeline_succeeds` | [사용 중단됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/185368) GitLab 17.11에서 `auto_merge` 옵션 지원. |
| `merge_request.auto_merge` | 머지 리퀘스트를 [자동 병합](../../user/project/merge_requests/auto_merge.md)으로 설정합니다. |
| `merge_request.remove_source_branch`         | 소스 브랜치를 병합할 때 제거하도록 머지 리퀘스트를 설정합니다. |
| `merge_request.squash`                       | 모든 커밋을 병합 시 단일 커밋으로 스쿼시하도록 머지 리퀘스트를 설정합니다. [GitLab 17.2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/158778)에서 도입되었습니다. |
| `merge_request.title="<title>"`              | 머지 리퀘스트의 제목을 설정합니다. 예: `git push -o merge_request.title="The title I want"`. |
| `merge_request.description="<description>"`  | 머지 리퀘스트의 설명을 설정합니다. 예: `git push -o merge_request.description="The description I want"`. |
| `merge_request.draft`                        | 머지 리퀘스트를 초안으로 표시합니다. 예: `git push -o merge_request.draft`. |
| `merge_request.milestone="<milestone>"`      | 머지 리퀘스트의 마일스톤을 설정합니다. 예: `git push -o merge_request.milestone="3.0"`. |
| `merge_request.label="<label>"`              | 머지 리퀘스트에 레이블을 추가합니다. 레이블이 없으면 생성됩니다. 예를 들어 두 개의 레이블: `git push -o merge_request.label="label1" -o merge_request.label="label2"`. |
| `merge_request.unlabel="<label>"`            | 머지 리퀘스트에서 레이블을 제거합니다. 예를 들어 두 개의 레이블: `git push -o merge_request.unlabel="label1" -o merge_request.unlabel="label2"`. |
| `merge_request.assign="<user>"`              | 머지 리퀘스트에 사용자를 할당합니다. 사용자 이름 또는 사용자 ID를 수락합니다. 예를 들어 두 사용자: `git push -o merge_request.assign="user1" -o merge_request.assign="user2"`. |
| `merge_request.unassign="<user>"`            | 머지 리퀘스트에서 할당된 사용자를 제거합니다. 사용자 이름 또는 사용자 ID를 수락합니다. 예를 들어 두 사용자: `git push -o merge_request.unassign="user1" -o merge_request.unassign="user2"`. |

### 시크릿 푸시 보호의 푸시 옵션 {#push-options-for-secret-push-protection}

푸시 옵션을 사용하여 [시크릿 푸시 보호](../../user/application_security/secret_detection/secret_push_protection/_index.md)를 건너뛸 수 있습니다.

| 푸시 옵션                    | 설명 | 예제 |
|--------------------------------|-------------|---------|
| `secret_push_protection.skip_all` | 이 푸시의 모든 커밋에 대해 시크릿 푸시 보호를 수행하지 마세요. | `git push -o secret_push_protection.skip_all` |

### 보안 정책의 푸시 옵션 {#push-options-for-security-policy}

푸시 옵션을 사용하여 [보안 정책을 우회](../../user/application_security/policies/merge_request_approval_policies.md#allowing-users-to-bypass-security-policies)할 수 있습니다.

| 푸시 옵션                    | 설명 | 예제 |
|--------------------------------|-------------|---------|
| `security_policy.bypass_reason` | 보안 정책에 대한 우회 이유를 설정합니다. | `git push -o security_policy.bypass_reason="Hot fix"` |

### GitGuardian 통합의 푸시 옵션 {#push-options-for-gitguardian-integration}

동일한 [시크릿 푸시 보호의 푸시 옵션](#push-options-for-secret-push-protection)을(를) 사용하여 GitGuardian 시크릿 검색을 건너뛸 수 있습니다.

| 푸시 옵션                    | 설명 | 예제 |
|--------------------------------|-------------|---------|
| `secret_detection.skip_all` | GitLab 17.2에서 사용 중단되었습니다. 대신 `secret_push_protection.skip_all`를 사용하세요. | `git push -o secret_detection.skip_all` |
| `secret_push_protection.skip_all` | GitGuardian 시크릿 검색을 수행하지 마세요. | `git push -o secret_push_protection.skip_all` |

### 푸시 옵션의 형식 {#formats-for-push-options}

푸시 옵션에 공백이 포함된 텍스트가 필요한 경우 텍스트를 큰따옴표(`"`)로 묶습니다. 공백이 없으면 따옴표를 생략할 수 있습니다. 몇 가지 예:

```shell
git push -o merge_request.label="Label with spaces"
git push -o merge_request.label=Label-with-no-spaces
```

여러 `-o` (또는 `--push-option`) 플래그를 사용하여 한 번에 여러 작업을 완료하기 위해 푸시 옵션을 결합합니다. 이 명령어는 새 머지 리퀘스트를 생성하고, 브랜치(`my-target-branch`)를 대상으로 하며, 자동 병합을 설정합니다:

```shell
git push -o merge_request.create -o merge_request.target=my-target-branch -o merge_request.auto_merge
```

기본 브랜치에서 다른 브랜치를 대상으로 새 머지 리퀘스트를 생성하려면:

```shell
git push -o merge_request.create -o merge_request.target=feature-branch
```

### 푸시 옵션 값의 줄 바꿈 {#newlines-in-push-option-values}

푸시 옵션 값은 리터럴 줄 바꿈 문자를 포함할 수 없습니다. 여러 줄 값을 직접 전달하면 Git은 다음 오류를 반환합니다:

```plaintext
fatal: push options must not have new line characters
```

푸시 옵션 값에 줄 바꿈을 포함하려면 (예: 머지 리퀘스트 설명에서) 리터럴 줄 바꿈 대신 `\n` 이스케이프 시퀀스를 사용합니다:

```shell
git push origin my-branch \
  -o merge_request.create \
  -o merge_request.title="My feature" \
  -o merge_request.description="# Summary\nDo something.\n\n# Testing\nDeploy this on your box."
```

GitLab은 `\n` 시퀀스를 머지 리퀘스트 설명의 줄 바꿈으로 변환합니다.

줄 바꿈 없이 단락을 구분하려면 `\n` 대신 HTML 단락 태그를 사용합니다:

```shell
git push origin my-branch \
  -o merge_request.create \
  -o merge_request.description="<p>First paragraph</p><p>Second paragraph</p>"
```

### 푸시를 위한 Git 별칭 생성 {#create-git-aliases-for-pushing}

Git 명령어에 푸시 옵션을 추가하면 매우 긴 명령어가 생성될 수 있습니다. 동일한 푸시 옵션을 자주 사용하는 경우 이에 대한 Git 별칭을 생성합니다. Git 별칭은 더 긴 Git 명령어의 명령줄 바로 가기입니다.

[자동 병합 Git 푸시 옵션](#push-options-for-merge-requests)에 대한 Git 별칭을 생성하고 사용하려면:

1. 터미널 창에서 다음 명령어를 실행합니다:

   ```shell
   git config --global alias.mwps "push -o merge_request.create -o merge_request.target=main -o merge_request.auto_merge"
   ```

1. 별칭을 사용하여 기본 브랜치(`main`)를 대상으로 하고 자동 병합하는 로컬 브랜치를 푸시하려면 다음 명령어를 실행합니다:

   ```shell
   git mwps origin <local-branch-name>
   ```

## 관련 항목 {#related-topics}

- [일반 Git 명령](commands.md)
