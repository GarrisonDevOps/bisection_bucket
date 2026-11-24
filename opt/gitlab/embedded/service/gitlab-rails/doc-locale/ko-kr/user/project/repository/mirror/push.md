---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 업스트림 리포지토리에서 수동으로 변경 사항을 받기 위한 푸시 미러를 생성합니다.
title: 푸시 미러링
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

_푸시 미러_는 업스트림 리포지토리에 생성된 커밋을 [미러](_index.md)하는 다운스트림 리포지토리입니다. 푸시 미러는 업스트림 리포지토리에 생성된 커밋 복사본을 수동으로 받습니다. 미러가 업스트림 리포지토리에서 분기되지 않도록 하려면 다운스트림 미러에 직접 커밋을 푸시하지 마세요. 대신 업스트림 리포지토리에 커밋을 푸시합니다.

[풀 미러링](pull.md)이 주기적으로 업스트림 리포지토리에서 업데이트를 검색하는 동안, 푸시 미러는 다음과 같은 경우에만 변경 사항을 받습니다:

- 커밋이 업스트림 GitLab 리포지토리에 푸시됩니다.
- 관리자가 [미러를 강제 업데이트](_index.md#force-an-update)합니다.

업스트림 리포지토리에 변경 사항을 푸시하면 푸시 미러가 5분 내에 받거나, **보호된 브랜치만 미러링** 설정이 켜져 있으면 1분 내에 받습니다.

브랜치가 기본 브랜치로 병합되고 소스 프로젝트에서 삭제되면 다음 푸시에서 원격 미러에서 삭제됩니다. 병합되지 않은 변경 사항이 있는 브랜치는 유지됩니다. 브랜치가 분기되면 **리포지토리 미러링** 섹션에 오류가 표시됩니다.

[GitLab 자동 모드](../../../../administration/silent_mode/_index.md)는 원격 미러로 푸시하고 원격 미러에서 풀하는 것을 비활성화합니다.

## 푸시 미러 제한 {#push-mirror-limits}

각 프로젝트는 최대 10개의 활성화된 푸시 미러를 가질 수 있습니다. 자세한 내용은 [프로젝트 푸시 미러의 최대 개수](../../../../administration/instance_limits.md#maximum-number-of-project-push-mirrors)를 참조하세요.

## 푸시 미러링 구성 {#configure-push-mirroring}

사전 요구 사항:

- GitLab 리포지토리와 원격 리포지토리가 동일한 객체 형식을 사용합니다. SHA-1과 SHA-256 리포지토리 간에 미러링할 수 없습니다.

기존 프로젝트의 푸시 미러링을 설정하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **리포지토리 미러링**을 확장합니다.
1. 리포지토리 URL을 입력합니다.
1. **미러 방향** 드롭다운 목록에서 **푸시**를 선택합니다.
1. **인증 방법**을 선택합니다. 자세한 내용은 [미러용 인증 방법](_index.md#authentication-methods-for-mirrors)을 참조하세요.
1. 필요한 경우 **보호된 브랜치만 미러링**을 선택합니다.
1. 원하는 경우 **다양한(divergent) 참조 유지**를 선택합니다.
1. 구성을 저장하려면 **리포지토리 미러링**을 선택합니다.

### API를 통한 푸시 미러 구성 {#configure-push-mirrors-through-the-api}

[원격 미러 API](../../../../api/remote_mirrors.md)를 통해 프로젝트 푸시 미러를 생성하고 수정할 수 있습니다.

## 다양한(divergent) 참조 유지 {#keep-divergent-refs}

기본적으로 원격(다운스트림) 미러의 참조(브랜치 또는 태그)가 로컬 리포지토리에서 분기되면 업스트림 리포지토리가 원격의 변경 사항을 덮어씁니다:

1. 리포지토리가 `main`와 `develop` 브랜치를 원격으로 미러링합니다.
1. 새로운 커밋이 원격 미러의 `develop`에 추가됩니다.
1. 다음 푸시는 원격 미러를 업스트림 리포지토리와 일치하도록 업데이트합니다.
1. 원격 미러의 `develop`에 추가된 새로운 커밋이 손실됩니다.

**다양한(divergent) 참조 유지**를 선택하면 변경 사항이 다르게 처리됩니다:

1. 원격 미러의 `develop` 브랜치에 대한 업데이트는 건너뜁니다.
1. 원격 미러의 `develop` 브랜치는 업스트림 리포지토리에 존재하지 않는 커밋을 보존합니다. 원격 미러에 있지만 업스트림에는 없는 참조는 건드리지 않습니다.
1. 업데이트는 실패로 표시됩니다.

미러를 생성한 후에는 **다양한(divergent) 참조 유지**의 값을 [원격 미러 API](../../../../api/remote_mirrors.md)를 통해서만 수정할 수 있습니다.

## GitLab에서 GitHub로 푸시 미러 설정 {#set-up-a-push-mirror-from-gitlab-to-github}

GitLab에서 GitHub로 커밋을 푸시하면 GitHub는 이메일 주소를 기반으로 커밋 속성을 결정합니다. 커밋 이메일 주소가 GitHub 사용자 계정의 확인된 이메일과 일치하면 GitHub는 해당 사용자에게 커밋을 할당합니다. 그렇지 않으면 커밋은 커밋 메타데이터의 이름과 이메일만 포함하여 속성이 없는 것으로 표시됩니다.

사전 요구 사항:

- GitHub [세분화된 개인 액세스 토큰](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#fine-grained-personal-access-tokens)으로 [리포지토리 콘텐츠](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=2022-11-28#repository-permissions-for-contents)에 대한 읽기 및 쓰기 권한이 있습니다. 리포지토리에 `.github/workflows` 디렉터리가 포함되어 있으면 [워크플로우](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=2022-11-28#repository-permissions-for-workflows)에 대한 읽기 및 쓰기 액세스 권한도 부여해야 합니다. 더 세분화된 액세스의 경우 특정 리포지토리에만 적용되도록 토큰을 구성합니다.

미러를 설정하려면:

1. **Git 리포지토리 URL**에 대해 이 형식으로 URL을 입력합니다:

   ```plaintext
   https://github.com/GROUP/PROJECT.git
   ```

   - `GROUP`: GitHub의 그룹입니다.
   - `PROJECT`: GitHub의 프로젝트입니다.

1. **사용자명**에 개인 액세스 토큰의 소유자의 사용자명을 입력합니다.
1. **비밀번호**에 GitHub 개인 액세스 토큰을 입력합니다.
1. **리포지토리 미러링**을 선택합니다.

미러링된 리포지토리가 나열됩니다. 예를 들어:

```plaintext
https://*****:*****@github.com/<your_github_group>/<your_github_project>.git
```

리포지토리는 곧 푸시됩니다. 푸시를 강제하려면 **지금 업데이트**({{< icon name="retry" >}})를 선택합니다.

## GitLab에서 AWS CodeCommit로 푸시 미러 설정 {#set-up-a-push-mirror-from-gitlab-to-aws-codecommit}

AWS CodeCommit 푸시 미러링은 GitLab 리포지토리를 AWS CodePipeline에 연결하는 가장 좋은 방법입니다. GitLab은 아직 소스 코드 관리(SCM) 제공자 중 하나로 지원되지 않습니다. 각각의 새로운 AWS CodePipeline은 상당한 AWS 인프라 설정이 필요합니다. 또한 브랜치당 개별 파이프라인이 필요합니다.

AWS CodeDeploy가 CodePipeline의 마지막 단계라면 다음 도구를 결합하여 배포를 생성할 수 있습니다:

- GitLab CI/CD 파이프라인.
- `.gitlab-ci.yml`의 최종 작업에서 AWS CLI를 사용하여 CodeDeploy에 배포합니다.

GitLab에서 AWS CodeCommit로 미러를 설정하려면:

1. AWS IAM 콘솔에서 IAM 사용자를 생성합니다.
1. 리포지토리 미러링을 위한 다음 최소 권한 권한을 **인라인 정책**으로 추가합니다.

   Amazon 리소스 이름(ARN)은 명시적으로 지역과 계정을 포함해야 합니다. 이 IAM 정책은 두 샘플 리포지토리에 대한 미러링 액세스 권한을 부여합니다. 이 권한들은 미러링에 필요한 최소(최소 권한) 권한인 것으로 테스트되었습니다:

   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Sid": "MinimumGitLabPushMirroringPermissions",
               "Effect": "Allow",
               "Action": [
                   "codecommit:GitPull",
                   "codecommit:GitPush"
               ],
               "Resource": [
                 "arn:aws:codecommit:us-east-1:111111111111:MyDestinationRepo",
                 "arn:aws:codecommit:us-east-1:111111111111:MyDemo*"
               ]
           }
       ]
   }
   ```

1. 사용자가 생성된 후 AWS IAM 사용자 이름을 선택합니다.
1. **보안 자격증명** 탭을 선택합니다.
1. **AWS CodeCommit용 HTTPS Git 자격증명**에서 **자격증명 생성**을 선택합니다.

   > [!note]
   > 이 Git 사용자 ID와 암호는 CodeCommit과의 통신에만 해당됩니다. 이를 이 사용자의 IAM 사용자 ID 또는 AWS 키와 혼동하지 마세요.

1. 특수 Git HTTPS 사용자 ID와 암호를 복사하거나 다운로드합니다.
1. AWS CodeCommit 콘솔에서 GitLab 리포지토리에서 미러링할 새로운 리포지토리를 생성합니다.
1. 새로운 리포지토리를 열고 오른쪽 위 모서리에서 **코드** > **HTTPS 복제**(**HTTPS 복제(GRC)** 아님)를 선택합니다.
1. GitLab에서 푸시 미러링될 리포지토리를 엽니다.
1. **설정** > **리포지토리**를 선택한 다음 **리포지토리 미러링**을 확장합니다.
1. **Git 리포지토리 URL** 필드를 이 형식으로 채우고, `<aws-region>`을 AWS 리전으로 바꾸고, `<your_codecommit_repo>`을 CodeCommit의 리포지토리 이름으로 바꿉니다:

   ```plaintext
   https://git-codecommit.<aws-region>.amazonaws.com/v1/repos/<your_codecommit_repo>
   ```

1. **인증 방법**에서 **사용자명과 암호**를 선택합니다.
1. **사용자명**에 AWS **특수 HTTPS Git 사용자 ID**를 입력합니다.
1. **비밀번호**에 AWS에서 이전에 생성한 특수 IAM Git 복제 사용자 ID 암호를 입력합니다.
1. CodeCommit의 경우 **보호된 브랜치만 미러링** 옵션을 유지합니다. 더 자주 푸시합니다(매 5분마다 매분으로).

   CodePipeline은 AWS CI 설정을 원하는 명명된 브랜치에 대해 개별 파이프라인 설정을 요구합니다. 동적 이름을 가진 기능 브랜치가 지원되지 않으므로, **보호된 브랜치만 미러링**을 구성하면 CodePipeline 통합과의 유연성 문제가 발생하지 않습니다. CodePipelines를 빌드하려는 명명된 브랜치를 모두 보호해야 합니다.

1. **리포지토리 미러링**을 선택합니다. 미러링된 리포지토리가 나타나는 것을 확인해야 합니다:

   ```plaintext
   https://*****:*****@git-codecommit.<aws-region>.amazonaws.com/v1/repos/<your_codecommit_repo>
   ```

푸시를 강제하여 미러링을 테스트하려면 **지금 업데이트**(반원형 화살표)를 선택합니다. **마지막으로 성공한 업데이트**에 날짜가 표시되면 미러링을 올바르게 구성한 것입니다. 올바르게 작동하지 않으면 빨간색 `error` 태그가 나타나고 오류 메시지를 호버 텍스트로 표시합니다.

## 2FA가 활성화된 다른 GitLab 인스턴스로 푸시 미러 설정 {#set-up-a-push-mirror-to-another-gitlab-instance-with-2fa-activated}

1. 대상 GitLab 인스턴스에서 `write_repository` 범위를 가진 [개인 액세스 토큰](../../../profile/personal_access_tokens.md)을 생성합니다.
1. 소스 GitLab 인스턴스:
   1. **Git 리포지토리 URL**을 이 형식으로 입력합니다: `https://<destination host>/<your_gitlab_group_or_name>/<your_gitlab_project>.git`.
   1. **사용자명** `oauth2`을 입력합니다.
   1. **비밀번호**를 입력합니다. 대상 GitLab 인스턴스에서 생성한 GitLab 개인 액세스 토큰을 사용합니다.
   1. **리포지토리 미러링**을 선택합니다.

## 관련 항목 {#related-topics}

- 리포지토리 미러링을 위한 [문제 해결](troubleshooting.md)입니다.
- [원격 미러 API](../../../../api/remote_mirrors.md)
