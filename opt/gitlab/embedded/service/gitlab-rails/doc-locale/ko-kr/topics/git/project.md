---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: "`git push`로 프로젝트 만들기"
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

`git push`을(를) 사용하여 로컬 프로젝트 리포지토리를 GitLab에 추가할 수 있습니다. 리포지토리를 추가하면 GitLab이 선택한 네임스페이스에 프로젝트를 만듭니다.

> [!note]
> `git push`을(를) 사용하여 이전에 사용했거나 [이름을 바꾼](../../user/project/working_with_projects.md#rename-a-repository) 경로로 프로젝트를 만들 수 없습니다. 이전에 사용했던 프로젝트 경로는 리다이렉트입니다. 새 프로젝트를 만드는 대신 리다이렉트는 푸시 시도를 이름이 바뀐 프로젝트 위치로 리다이렉트합니다. 이전에 사용했거나 이름이 바뀐 프로젝트에 대한 새 프로젝트를 만들려면 UI 또는 [Projects API](../../api/projects.md#create-a-project)를 사용합니다.

전제 조건:

<!--- To push with SSH, you must have [an SSH key](../ssh.md) that is
  [added to your GitLab account](../ssh.md#add-an-ssh-key-to-your-gitlab-account).
-->
- [네임스페이스](../../user/namespace/_index.md)에 새 프로젝트를 추가할 수 있는 권한이 있어야 합니다. 권한을 확인하려면:

  1. 상단 바에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
  1. 오른쪽 위 모서리에서 **새 프로젝트**가 표시되는지 확인합니다.

  필요한 권한이 없으면 GitLab 관리자에게 문의합니다.

`git push`(으)로 프로젝트를 만들려면:

1. 다음 중 하나를 사용하여 로컬 리포지토리를 GitLab에 푸시합니다:

   - SSH 사용:

     - 프로젝트에서 표준 포트 22를 사용하는 경우 다음을 실행합니다:

       ```shell
       git push --set-upstream git@gitlab.example.com:namespace/myproject.git main
       ```

     - 프로젝트에서 표준이 아닌 포트 번호가 필요한 경우 다음을 실행합니다:

       ```shell
       git push --set-upstream ssh://git@gitlab.example.com:00/namespace/myproject.git main
       ```

   - HTTP를 사용하여 다음을 실행합니다:

     ```shell
     git push --set-upstream https://gitlab.example.com/namespace/myproject.git master
     ```

     다음 값을 바꿉니다.

     - `gitlab.example.com`(을)를 Git 리포지토리를 호스팅하는 머신의 도메인 이름으로 바꿉니다.
     - `namespace`(을)를 [네임스페이스](../../user/namespace/_index.md) 이름으로 바꿉니다.
     - `myproject`(을)를 프로젝트 이름으로 바꿉니다.
     - 포트를 지정하는 경우 `00`(을)를 프로젝트에 필요한 포트 번호로 변경합니다.
     - 선택사항. 기존 리포지토리 태그를 내보내려면 `--tags` 플래그를 `git push` 명령에 추가합니다.

1. 선택사항. 원격 저장소를 구성합니다:

   ```shell
   git remote add origin https://gitlab.example.com/namespace/myproject.git
   ```

`git push` 작업이 완료되면 GitLab에 다음 메시지가 표시됩니다:

```shell
remote: The private project namespace/myproject was created.
```

새 프로젝트를 보려면 `https://gitlab.example.com/namespace/myproject`(으)로 이동합니다. 기본적으로 프로젝트의 가시성은 **비공개**로 설정되어 있지만 [프로젝트의 가시성을 변경](../../user/public_access.md#change-project-visibility)할 수 있습니다.

## 관련 항목 {#related-topics}

- [빈 프로젝트 만들기](../../user/project/_index.md)
- [템플릿에서 프로젝트 만들기](../../user/project/_index.md#create-a-project-from-a-built-in-template)
- [로컬 머신에 리포지토리 복제](clone.md)
