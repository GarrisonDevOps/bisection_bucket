---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 모노레포 패키지 관리 워크플로우
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

모노레포 프로젝트를 패키지 레지스트리로 사용하여 여러 프로젝트에 패키지를 게시합니다.

## 프로젝트 및 자식 프로젝트에 패키지 게시 {#publish-packages-to-a-project-and-its-child-projects}

프로젝트 및 자식 프로젝트에 패키지를 게시하려면 각 패키지에 대한 구성 파일을 추가해야 합니다. 특정 패키지 관리자에 대해 패키지를 구성하는 방법을 알아보려면 [지원되는 패키지 관리자](../package_registry/supported_functionality.md)를 참조하세요.

다음 예에서는 [npm](../npm_registry/_index.md)을 사용하여 프로젝트 및 자식 프로젝트에 패키지를 게시하는 방법을 보여줍니다.

사전 요구 사항:

- [개인 액세스 토큰](../../profile/personal_access_tokens.md)(범위가 `api`(으)로 설정됨).
- 테스트 프로젝트.

이 예에서 `MyProject`은 부모 프로젝트입니다. `components` 디렉터리에 `ChildProject`라는 자식 프로젝트를 포함합니다:

```plaintext
MyProject/
  |- src/
  |   |- components/
  |       |- ChildProject/
  |- package.json
```

`MyProject`에 대한 패키지를 게시하려면:

1. `MyProject` 디렉터리로 이동합니다.
1. `npm init`을(를) 실행하여 프로젝트를 초기화합니다. 패키지 이름이 [명명 규칙](../npm_registry/_index.md#naming-convention)을 따르는지 확인하세요.
1. `.npmrc` 파일을 생성합니다. 레지스트리 URL 및 프로젝트 엔드포인트를 포함합니다. 예를 들어:

   ```yaml
   //gitlab.example.com/api/v4/projects/<project_id>/packages/npm/:_authToken="${NPM_TOKEN}"
   @scope:registry=https://gitlab.example.com/api/v4/projects/<project_id>/packages/npm/
   ```

1. 명령줄에서 패키지를 게시합니다. `<token>`을(를) 개인 액세스 토큰으로 바꿉니다:

   ```shell
   NPM_TOKEN=<token> npm publish
   ```

> [!warning]
> GitLab 토큰(또는 모든 토큰)을 `.npmrc` 파일이나 리포지토리에 커밋할 수 있는 기타 파일에 직접 하드코딩하지 마세요.

`MyProject`에 대한 패키지가 프로젝트의 패키지 레지스트리에 게시된 것을 확인할 수 있습니다.

`ChildProject`에 패키지를 게시하려면 같은 단계를 따릅니다. `.npmrc` 파일의 내용은 `MyProject`에 추가한 파일과 동일할 수 있습니다.

`ChildProject`에 대한 패키지를 게시한 후 프로젝트의 패키지 레지스트리에서 패키지를 확인할 수 있습니다.

## 다른 프로젝트에 패키지 게시 {#publishing-packages-to-other-projects}

패키지는 GitLab의 프로젝트와 연결되어 있습니다. 그러나 패키지는 해당 프로젝트의 코드와 연결되지 않습니다.

예를 들어 npm 또는 Maven용 패키지를 구성할 때 `project_id`은 패키지가 게시되는 레지스트리 URL을 설정합니다.

예를 들어:

- npm: `https://gitlab.example.com/api/v4/projects/<project_id>/packages/npm/`
- maven: `https://gitlab.example.com/api/v4/projects/<project_id>/packages/maven/`

레지스트리 URL에서 `project_id`을(를) 다른 프로젝트로 변경하면 패키지가 해당 프로젝트에 게시됩니다.

`project_id`을(를) 변경하여 코드와 별도로 여러 패키지를 하나의 프로젝트에 게시할 수 있습니다. 자세한 내용은 [모든 패키지를 하나의 GitLab 프로젝트에 저장](project_registry.md)을 참조하세요.
