---
stage: Solutions Architecture
group: Solutions Architecture
info: This page is owned by the Solutions Architecture team.
title: AWS CodePipeline
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

GitLab 프로젝트를 사용하여 [AWS CodePipeline](https://aws.amazon.com/codepipeline/)을 통해 코드 변경 사항을 빌드, 테스트 및 배포할 수 있습니다. 이를 위해 다음을 사용합니다:

- GitLab.com 계정을 AWS에 연결하는 AWS CodeStar Connections.
- 코드 변경 사항에 따라 파이프라인을 자동으로 시작하는 해당 연결.

## AWS CodePipeline에서 GitLab으로의 연결 생성 {#create-a-connection-from-aws-codepipeline-to-gitlab}

사전 요구 사항:

- AWS CodePipeline과 연결 중인 GitLab 프로젝트에 대한 소유자 역할이 있어야 합니다.
- AWS에서 연결을 생성할 수 있는 적절한 권한이 있어야 합니다.
- 지원되는 AWS 리전을 사용해야 합니다. 지원되지 않는 리전([AWS 설명서](https://docs.aws.amazon.com/codepipeline/latest/userguide/connections-gitlab.html)에도 나열됨)은 다음과 같습니다:
  - 아시아 태평양 (홍콩).
  - 아프리카 (케이프타운).
  - 중동 (바레인).
  - 유럽 (취리히).
  - AWS GovCloud (US-West 및 US-East).

GitLab.com의 프로젝트에 연결을 생성하려면 AWS Management Console 또는 AWS Command Line Interface(AWS CLI)를 사용할 수 있습니다.

### AWS Management Console 사용 {#use-the-aws-management-console}

AWS CodePipeline에서 새 파이프라인이나 기존 파이프라인을 GitLab.com과 연결하려면 먼저 AWS 연결이 GitLab 계정을 사용하도록 승인해야 합니다.

1. AWS Management Console에 로그인하고 [AWS Developer Tools 콘솔](https://console.aws.amazon.com/codesuite/settings/connections)을 엽니다.
1. **설정** > **연결** > **연결 생성**을 선택합니다.
1. **공급자 선택**에서 **GitLab**을 선택합니다.
1. **연결 이름**에서 생성할 연결의 이름을 입력하고 **GitLab에 연결**을 선택합니다.
1. GitLab 로그인 페이지에서 자격 증명을 입력하고 **로그인**을 선택합니다.
1. 연결이 GitLab 계정에 액세스할 수 있는 권한을 요청하는 메시지가 있는 권한 부여 페이지가 표시됩니다. **권한 부여**를 선택합니다.
1. 브라우저가 연결 콘솔 페이지로 돌아갑니다. **GitLab 연결 생성** 섹션에서 새 연결이 **연결 이름**에 표시됩니다.
1. **GitLab에 연결**을 선택합니다. 연결이 성공적으로 생성되면 성공 배너가 표시됩니다. 연결 세부 정보가 **연결 설정** 페이지에 표시됩니다.

AWS CodeSuite를 GitLab.com에 연결했으므로 GitLab 프로젝트를 활용하는 AWS CodePipeline에서 파이프라인을 생성하거나 편집할 수 있습니다.

1. [AWS CodePipeline 콘솔](https://console.aws.amazon.com/codesuite/codepipeline/start)에 로그인합니다.
1. 파이프라인을 생성하거나 편집합니다:
   - 파이프라인을 생성하는 경우:
     - 첫 번째 화면의 필드를 완료하고 **다음**을 선택합니다.
     - **소스** 페이지의 **소스 공급자** 섹션에서 **GitLab**을 선택합니다.
   - 기존 파이프라인을 편집하는 경우:
     - **편집** > **스테이지 편집**을 선택하여 소스 작업을 추가하거나 편집합니다.
     - **작업 편집** 페이지의 **작업 이름** 섹션에서 작업의 이름을 입력합니다.
     - **작업 공급자**에서 **GitLab**을 선택합니다.
1. **연결**에서 이전에 생성한 연결을 선택합니다.
1. **리포지토리 이름**에서 GitLab 프로젝트의 이름을 선택하려면 네임스페이스와 모든 하위 그룹이 포함된 전체 프로젝트 경로를 지정합니다. 예를 들어 그룹 수준 프로젝트의 경우 프로젝트 이름을 다음 형식으로 입력합니다. `group-name/subgroup-name/project-name` 네임스페이스가 있는 프로젝트 경로는 GitLab의 URL에 있습니다. Web IDE 또는 원본 보기에서 URL을 복사하지 마십시오. 다른 특수 URL 세그먼트가 포함될 수 있습니다. 대화 상자에서 옵션을 선택하거나 새 경로를 수동으로 입력할 수도 있습니다. 다음에 대한 자세한 내용:
   - 경로 및 네임스페이스는 [프로젝트 API](../../../api/projects.md#retrieve-a-project)의 `path_with_namespace` 필드를 참조하세요.
   - GitLab의 네임스페이스는 [네임스페이스](../../namespace/_index.md)를 참조하세요.

1. **브랜치 이름**에서 파이프라인이 소스 변경 사항을 감지하도록 할 브랜치를 선택합니다. 브랜치 이름이 자동으로 표시되지 않으면 다음 중 하나 때문일 수 있습니다:
   - 프로젝트에 대한 소유자 역할이 없습니다.
   - 프로젝트 이름이 유효하지 않습니다.
   - 사용된 연결이 프로젝트에 대한 액세스 권한이 없습니다.

1. **출력 아티팩트 형식**에서 아티팩트의 형식을 선택합니다. 저장하려면:
   - 기본 방법을 사용하여 GitLab 작업의 출력 아티팩트를 저장하려면 **CodePipeline 기본값**을 선택합니다. 작업은 GitLab 리포지토리에서 파일에 액세스하고 아티팩트를 파이프라인 아티팩트 저장소의 ZIP 파일에 저장합니다.
   - 리포지토리에 대한 URL 참조가 포함된 JSON 파일을 다운스트림 작업이 Git 명령을 직접 수행할 수 있도록 선택하려면 **전체 복제**를 선택합니다. 이 옵션은 CodeBuild 다운스트림 작업에서만 사용할 수 있습니다. 이 옵션을 선택하려면:
     - [CodeBuild 프로젝트 서비스 역할의 권한 업데이트](https://docs.aws.amazon.com/codepipeline/latest/userguide/troubleshooting.html#codebuild-role-connections).
     - [GitHub 파이프라인 소스에서 전체 복제를 사용하는 방법에 대한 AWS CodePipeline 튜토리얼](https://docs.aws.amazon.com/codepipeline/latest/userguide/tutorials-github-gitclone.html)을 따릅니다.
1. 소스 작업을 저장하고 계속합니다.

### AWS CLI 사용 {#use-the-aws-cli}

AWS CLI를 사용하여 연결을 생성하려면:

- `create-connection` 명령을 사용합니다.
- AWS 콘솔로 이동하여 GitLab.com 계정으로 인증합니다.
- GitLab 프로젝트를 AWS CodePipeline에 연결합니다.

`create-connection` 명령을 사용하려면:

1. 터미널(Linux, macOS 또는 Unix) 또는 명령 프롬프트(Windows)를 엽니다. AWS CLI를 사용하여 `create-connection` 명령을 실행하고 연결에 대한 `--provider-type` 및 `--connection-name`을(를) 지정합니다. 이 예에서 타사 공급자 이름은 `GitLab`이고 지정된 연결 이름은 `MyConnection`입니다.

   ```shell
   aws codestar-connections create-connection --provider-type GitLab --connection-name MyConnection
   ```

   성공하면 이 명령은 연결의 Amazon Resource Name(ARN) 정보를 반환합니다. 예를 들어:

   ```json
   {
   "ConnectionArn": "arn:aws:codestar-connections:us-west-2:account_id:connection/aEXAMPLE-8aad-4d5d-8878-dfcab0bc441f"
   }
   ```

1. 새 연결은 기본적으로 `PENDING` 상태로 생성됩니다. 콘솔을 사용하여 연결의 상태를 `AVAILABLE`(으)로 변경합니다.
1. [AWS 콘솔을 사용하여 연결 완료](#use-the-aws-management-console) 보류 중인 GitLab 연결을 선택했는지 확인합니다. **연결 생성**을 선택하지 마십시오.

## 관련 항목 {#related-topics}

- [AWS CodePipeline이 GitLab을 지원한다는 공지](https://aws.amazon.com/about-aws/whats-new/2023/08/aws-codepipeline-supports-gitlab/)
- [GitLab 연결 - AWS CodePipeline](https://docs.aws.amazon.com/codepipeline/latest/userguide/connections-gitlab.html)
- [GitLab에 대한 연결 생성 - Developer Tools 콘솔](https://docs.aws.amazon.com/dtconsole/latest/userguide/connections-create-gitlab.html)
- [Bitbucket, GitHub, GitHub Enterprise Server 및 GitLab 작업용 CodeStarSourceConnection - AWS CodePipeline](https://docs.aws.amazon.com/codepipeline/latest/userguide/action-reference-CodestarConnectionSource.html)
