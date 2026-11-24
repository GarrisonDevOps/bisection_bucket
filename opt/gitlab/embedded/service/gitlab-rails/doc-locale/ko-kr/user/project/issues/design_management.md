---
stage: Plan
group: Portfolio Planning
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 디자인 관리 (더 이상 사용되지 않음)
---

<!--- start_remove The following content will be removed on remove_date: '2027-05-15' -->

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!warning]
> 이 기능은 GitLab 18.6에서 [더 이상 사용되지 않으며](../../../update/deprecations.md#design-management-deprecated) 20.0에서 제거될 예정입니다. 이것은 주요 변경 사항입니다. GitLab 20.0 이상에서는 사용자가 더 이상 새 디자인을 업로드할 수 없습니다. 기존 디자인은 GitLab 21.0까지 읽기 전용 모드에서 사용 가능하므로 사용자는 필요에 따라 디자인을 저장할 수 있습니다. GitLab은 디자이너가 이미 사용 중인 도구와 더 잘 통합되는 대안을 모색하고 있습니다.

<!--- end_remove -->

디자인 관리를 사용하면 디자인 자산(와이어프레임 및 목업 포함)을 GitLab 이슈에 업로드하고 한 곳에 저장할 수 있습니다. 제품 디자이너, 제품 관리자 및 엔지니어는 단일 소스를 기준으로 디자인에 대해 협력할 수 있습니다.

팀과 디자인의 목업을 공유하거나 시각적 회귀를 확인하고 해결할 수 있습니다.

<i class="fa-youtube-play" aria-hidden="true"></i> 동영상 개요는 [디자인 관리](https://www.youtube.com/watch?v=CCMtCqdK_aM)를 참조하세요.
<!-- Video published on 2019-07-11 -->

## 사전 요구 사항 {#prerequisites}

- [Git 대용량 파일 저장소(LFS)](../../../topics/git/lfs/_index.md)를 활성화해야 합니다:
  - GitLab.com에서는 LFS가 이미 활성화되어 있습니다.
  - GitLab Self-Managed 인스턴스에서는 GitLab 관리자가 [LFS를 전역적으로 활성화](../../../administration/lfs/_index.md)해야 합니다.
  - GitLab.com 및 GitLab Self-Managed 인스턴스 모두에서 LFS는 [프로젝트 자체에 대해 활성화](../settings/_index.md#configure-project-features-and-permissions)되어야 합니다. 전역적으로 활성화되면 LFS는 모든 프로젝트에 대해 기본적으로 활성화됩니다. 프로젝트에서 비활성화한 경우 다시 활성화해야 합니다.

  디자인은 LFS 개체로 저장됩니다. 이미지 썸네일은 다른 업로드로 저장되며 프로젝트와 연결되지 않고 특정 디자인 모델과 연결됩니다.

  GitLab 관리자는 **운영자** > **프로젝트**로 이동한 다음 해당 프로젝트를 선택하여 해시 저장된 프로젝트의 상대 경로를 확인할 수 있습니다. **상대 경로** 필드는 값에 `@hashed`를 포함합니다.

요구 사항이 충족되지 않으면 **디자인** 섹션에서 알림을 받습니다.

## 지원되는 파일 형식 {#supported-file-types}

다음 유형의 파일을 디자인으로 업로드할 수 있습니다:

- BMP
- GIF
- ICO
- JPEG
- JPG
- PNG
- TIFF
- WEBP

PDF 파일에 대한 지원은 [이슈 32811](https://gitlab.com/gitlab-org/gitlab/-/issues/32811)에서 추적됩니다.

## 디자인 보기 {#view-a-design}

**디자인** 섹션은 이슈 설명에 있습니다.

사전 요구 사항:

- 프로젝트에 대한 게스트, 플래너, 리포터, 개발자, 유지보수자 또는 소유자 역할이 필요합니다.

디자인을 보려면:

1. 이슈로 이동합니다.
1. **디자인** 섹션에서 보려는 디자인 이미지를 선택합니다.

선택한 디자인이 열립니다. 그 후 [확대](#zoom-in-on-a-design)하거나 [댓글을 추가](#add-a-comment-to-a-design)할 수 있습니다.

![업로드된 디자인 목업을 표시하는 GitLab 이슈의 '디자인' 섹션.](img/design_management_v14_10.png)

디자인을 볼 때 다른 디자인으로 이동할 수 있습니다. 이렇게 하려면:

- 오른쪽 위 모서리에서 **이전 디자인으로 이동**({{< icon name="chevron-lg-left" >}}) 또는 **다음 디자인으로 이동**({{< icon name="chevron-lg-right" >}})을 선택합니다.
- 키보드에서 <kbd>왼쪽</kbd> 또는 <kbd>오른쪽</kbd>을 누릅니다.

이슈 보기로 돌아가려면:

- 왼쪽 위 모서리에서 닫기 아이콘({{< icon name="close" >}})을 선택합니다.
- 키보드에서 <kbd>Esc</kbd>를 누릅니다.

디자인이 추가되면 녹색 아이콘({{< icon name="plus-square" >}})이 이미지 썸네일에 표시됩니다. 디자인이 현재 버전에서 [변경](#add-a-new-version-of-a-design)되면 파란색 아이콘({{< icon name="file-modified-solid" >}})이 표시됩니다.

### 디자인 확대 {#zoom-in-on-a-design}

이미지를 확대 및 축소하여 디자인을 더 자세히 살펴볼 수 있습니다:

- 확대 양을 제어하려면 이미지 아래의 더하기(`+`) 및 빼기(`-`)를 선택합니다.
- 확대 수준을 재설정하려면 다시 실행 아이콘({{< icon name="redo" >}})을 선택합니다.

확대된 이미지를 이동하려면 이미지를 드래그합니다.

## 액세스 토큰으로 디자인 이미지 다운로드 {#download-a-design-image-with-an-access-token}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/246866)되었습니다.

{{< /history >}}

액세스 토큰을 사용하여 브라우저 세션이 없는 모바일 앱, 통합 및 익스포터와 같은 API 클라이언트에서 디자인 이미지를 다운로드합니다.

사전 요구 사항:

- 다음 토큰 중 하나가 필요합니다:
  - [개인 액세스 토큰](../../profile/personal_access_tokens.md) 또는 [OAuth 2.0 토큰](../../../api/oauth2.md)(`api` 또는 `read_api` 범위 포함).
  - [세분화된 개인 액세스 토큰](../../../auth/tokens/fine_grained_access_tokens.md)(프로젝트에 대한 **작업 항목: 읽기** 권한 포함).
- [디자인을 볼](#view-a-design) 수 있는 권한이 필요합니다.

프로젝트 액세스 토큰, 그룹 액세스 토큰 또는 서비스 계정 토큰을 사용하여 디자인 이미지를 다운로드할 수 없습니다.

디자인 이미지를 다운로드하려면:

1. GraphQL API에서 이미지 URL을 가져옵니다. 432x230 픽셀 이하의 미리보기의 경우 `image` 대신 `imageV432x230` 필드를 사용합니다:

   ```graphql
   query {
     project(fullPath: "my-group/my-project") {
       issue(iid: "1") {
         designCollection {
           designs {
             nodes {
               filename
               image
             }
           }
         }
       }
     }
   }
   ```

1. 이미지 URL을 요청하고 `PRIVATE-TOKEN` 헤더에서 토큰을 전달합니다:

   ```shell
   curl --output design.png --header "PRIVATE-TOKEN: <your_access_token>" "<image_url>"
   ```

   OAuth 2.0 토큰의 경우 `Authorization: Bearer <oauth_token>` 헤더를 대신 사용합니다. 요청 헤더에서 토큰을 보내야 합니다. `private_token`와 같은 쿼리 문자열 매개변수의 토큰은 허용되지 않습니다.

## 이슈에 디자인 추가 {#add-a-design-to-an-issue}

{{< history >}}

- 이슈에 디자인을 추가하기 위한 최소 역할이 GitLab 17.7에서 리포터에서 플래너로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

사전 요구 사항:

- 프로젝트에 대한 플래너, 리포터, 개발자, 유지보수자 또는 소유자 역할이 필요합니다.
- 업로드된 파일의 이름은 255자 이하여야 합니다.

이슈에 디자인을 추가하려면:

1. 이슈로 이동합니다.
1. 다음 중 하나를 선택합니다.
   - **디자인 업로드**를 선택한 다음 파일 브라우저에서 이미지를 선택합니다. 한 번에 최대 10개의 파일을 선택할 수 있습니다.
     <!-- vale gitlab_base.SubstitutionWarning = NO -->
   - **클릭하여 업로드**를 선택한 다음 파일 브라우저에서 이미지를 선택합니다. 한 번에 최대 10개의 파일을 선택할 수 있습니다.
     <!-- vale gitlab_base.SubstitutionWarning = YES -->

   - 파일 브라우저에서 파일을 끌어 **디자인** 섹션의 드롭 영역에 놓습니다.

     ![이슈 페이지에서 디자인을 끌어서 놓아 새로운 디자인을 업로드합니다.](img/design_drag_and_drop_uploads_v13_2.png)

   - 스크린샷을 찍거나 로컬 이미지 파일을 클립보드에 복사하고 드롭 영역 위에 커서를 놓은 다음 <kbd>Control</kbd> 또는 <kbd>Command</kbd>+<kbd>V</kbd>를 누릅니다.

     이런 식으로 이미지를 붙여넣을 때 다음을 염두에 두세요:

     - 한 번에 하나의 이미지만 붙여넣을 수 있습니다. 여러 복사된 파일을 붙여넣으면 첫 번째 파일만 업로드됩니다.
     - 스크린샷을 붙여넣는 경우 이미지는 다음과 같은 생성된 이름의 PNG 파일로 추가됩니다: `design_<timestamp>.png`.
     - Internet Explorer에서는 지원되지 않습니다.

## 디자인의 새 버전 추가 {#add-a-new-version-of-a-design}

{{< history >}}

- 디자인의 새 버전을 추가하기 위한 최소 역할이 GitLab 17.7에서 리포터에서 플래너로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

디자인에 대한 논의가 계속되면 새 버전의 디자인을 업로드할 수 있습니다.

사전 요구 사항:

- 프로젝트에 대한 플래너, 리포터, 개발자, 유지보수자 또는 소유자 역할이 필요합니다.

이렇게 하려면 [동일한 파일 이름으로 디자인을 추가](#add-a-design-to-an-issue)하세요.

모든 디자인 버전을 찾으려면 **디자인** 섹션 맨 위의 드롭다운 목록을 사용합니다. **최신 버전 표시** 또는 **버전 #N 표시**로 표시됩니다.

### 건너뛴 디자인 {#skipped-designs}

기존 업로드된 디자인과 동일한 파일 이름으로 이미지를 업로드하면 건너뜁니다. 이는 디자인의 새 버전이 생성되지 않음을 의미합니다. 디자인을 건너뛰면 경고 메시지가 표시됩니다.

## 디자인 아카이브 {#archive-a-design}

{{< history >}}

- 디자인을 아카이브하기 위한 최소 역할이 GitLab 17.7에서 리포터에서 플래너로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

개별 디자인을 아카이브하거나 여러 디자인을 한 번에 아카이브할 수 있습니다.

아카이브된 디자인은 영구적으로 손실되지 않습니다. [이전 버전](#add-a-new-version-of-a-design)을 찾을 수 있습니다.

디자인을 아카이브하면 URL이 변경됩니다. 디자인을 최신 버전에서 사용할 수 없으면 URL의 버전을 사용하여서만 연결할 수 있습니다.

사전 요구 사항:

- 프로젝트에 대한 플래너, 리포터, 개발자, 유지보수자 또는 소유자 역할이 필요합니다.
- 디자인의 최신 버전만 아카이브할 수 있습니다.

단일 디자인을 아카이브하려면:

1. 디자인을 선택하여 확대하여 봅니다.
1. 오른쪽 위 모서리에서 **디자인 아카이빙**({{< icon name="archive" >}})을 선택합니다.
1. **디자인 아카이빙**을 선택합니다.

여러 디자인을 한 번에 아카이브하려면:

1. 아카이브할 디자인에 대한 체크박스를 선택합니다.
1. **아카이브 선택됨**을 선택합니다.

## 디자인 관리 데이터 지속성 {#design-management-data-persistence}

- 디자인 관리 데이터는 다음 경우에 삭제되지 않습니다:
  - [프로젝트가 삭제](https://gitlab.com/gitlab-org/gitlab/-/issues/13429)됩니다.
  - [이슈가 삭제](https://gitlab.com/gitlab-org/gitlab/-/issues/13427)됩니다.

### 디자인 관리 데이터 복제 {#replicate-design-management-data}

디자인 관리 데이터는 [복제](../../../administration/geo/replication/datatypes.md#replicated-data-types)될 수 있으며 Geo에 의해 검증됩니다. 자세한 내용은 [이슈 355660](https://gitlab.com/gitlab-org/gitlab/-/issues/355660)을 참조하세요.

## 설명을 위한 Markdown 및 서식 있는 텍스트 편집기 {#markdown-and-rich-text-editors-for-descriptions}

디자인 설명에서 Markdown 및 서식 있는 텍스트 편집기를 사용할 수 있습니다. GitLab 전체에서 댓글에 사용하는 것과 동일한 편집기입니다.

## 디자인 순서 변경 {#reorder-designs}

디자인을 새로운 위치로 드래그하여 순서를 변경할 수 있습니다.

## 디자인에 댓글 추가 {#add-a-comment-to-a-design}

업로드된 디자인에서 [논의](../../discussions/_index.md)를 시작할 수 있습니다. 방법은 다음과 같습니다:

1. 이슈로 이동합니다.
1. 디자인을 선택합니다.
1. 이미지를 선택합니다. 핀이 해당 위치에 생성되어 논의의 위치를 식별합니다.
1. 메시지를 입력합니다.
1. **댓글**를 선택합니다.

이미지를 드래그하여 핀의 위치를 조정할 수 있습니다. 디자인 레이아웃이 변경되었거나 새 핀을 추가할 수 있도록 핀을 이동할 때 사용합니다.

새 논의 스레드는 서로 다른 핀 번호를 가지며 이를 사용하여 참조할 수 있습니다.

새 논의는 이슈 활동에 출력되므로 관련된 모든 사람이 논의에 참여할 수 있습니다.

## 디자인에서 댓글 삭제 {#delete-a-comment-from-a-design}

{{< history >}}

- 디자인에서 댓글을 삭제하기 위한 최소 역할이 GitLab 17.7에서 리포터에서 플래너로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.

{{< /history >}}

사전 요구 사항:

- 프로젝트에 대한 플래너, 리포터, 개발자, 유지보수자 또는 소유자 역할이 필요합니다.

디자인에서 댓글을 삭제하려면:

1. 삭제하려는 댓글에서 **추가 작업** {{< icon name="ellipsis_v" >}} > **댓글 삭제**를 선택합니다.
1. 확인 대화에서 **댓글 삭제**를 선택합니다.

## 디자인에서 논의 스레드 해결 {#resolve-a-discussion-thread-on-a-design}

디자인의 일부에 대한 논의를 마치면 논의 스레드를 해결할 수 있습니다.

스레드를 해결됨 또는 열기로 표시하려면:

- 논의의 첫 번째 댓글의 오른쪽 위 모서리에서 **스레드 해결** 또는 **스레드 다시 열기**({{< icon name="check-circle" >}})를 선택합니다.
- 스레드에 새 댓글을 추가하고 **스레드 해결** 체크박스를 선택하거나 선택 해제합니다.

논의 스레드를 해결하면 스레드 내 노트와 관련된 모든 미결 [할 일 항목](../../todos.md)도 완료로 표시됩니다. 작업을 트리거하는 사용자에 대한 할 일 항목만 영향을 받습니다.

새 논의를 위한 공간을 확보하기 위해 해결된 댓글 핀이 디자인에서 사라집니다. 해결된 논의를 다시 방문하려면 표시된 스레드 아래에서 **해결된 댓글**을 확장합니다.

## 디자인을 위한 할 일 항목 추가 {#add-a-to-do-item-for-a-design}

디자인에 [할 일 항목](../../todos.md)을 추가하려면 디자인 사이드바에서 **할 일 항목 추가**를 선택합니다.

## Markdown에서 디자인 참조 {#refer-to-a-design-in-markdown}

[Markdown](../../markdown.md) 텍스트 상자에서 디자인을 참조할 수 있습니다. 댓글이나 설명에 디자인의 원본 URL을 붙여넣습니다. 그러면 짧은 참조로 표시됩니다.

예를 들어 디자인을 다음과 같이 참조하는 경우:

```markdown
See https://gitlab.com/gitlab-org/gitlab/-/issues/13195/designs/Group_view.png.
```

GitLab은 자동으로 원본 URL을 약칭 [참조](../../markdown.md#gitlab-specific-references)로 렌더링합니다: `See #13195[Group_view.png].`

이미지에 연결하는 것은 댓글이나 설명에서 [이미지를 포함](../../markdown.md#images)하는 것과 다릅니다. 이런 식으로 디자인을 포함할 수 없습니다.

## 디자인 활동 기록 {#design-activity-records}

디자인에 대한 사용자 활동 이벤트(생성, 삭제 및 업데이트)는 GitLab에서 추적되며 [사용자 프로필](../../profile/_index.md#access-your-user-profile), [그룹](../../group/manage.md#view-group-activity) 및 [프로젝트](../working_with_projects.md#view-project-activity) 활동 페이지에 표시됩니다.

## GitLab-Figma 플러그인 {#gitlab-figma-plugin}

GitLab-Figma 플러그인을 사용하여 Figma에서 GitLab의 이슈로 디자인을 직접 업로드할 수 있습니다.

Figma에서 플러그인을 사용하려면 [Figma 디렉토리](https://www.figma.com/community/plugin/860845891704482356/gitlab)에서 설치하고 개인 액세스 토큰을 통해 GitLab에 연결합니다.

자세한 내용은 [플러그인 설명서](https://gitlab.com/gitlab-org/gitlab-figma-plugin/-/wikis/home)를 참조하세요.

## 문제 해결 {#troubleshooting}

디자인 관리를 사용할 때 다음 문제가 발생할 수 있습니다.

### 디자인을 찾을 수 없음 {#could-not-find-design}

`Could not find design`라는 오류가 표시될 수 있습니다.

이 문제는 디자인이 [아카이브](#archive-a-design)되어 최신 버전에서 사용할 수 없고 따라간 링크가 버전을 지정하지 않을 때 발생합니다.

디자인을 아카이브하면 URL이 변경됩니다. 디자인을 최신 버전에서 사용할 수 없으면 URL의 버전을 사용하여서만 연결할 수 있습니다.

예를 들어, `https://gitlab.example.com/mygroup/myproject/-/issues/123456/designs/menu.png?version=503554`입니다. `menu.png`에 더 이상 `https://gitlab.example.com/mygroup/myproject/-/issues/123456/designs/menu.png`로 액세스할 수 없습니다.

해결 방법은 **디자인** 섹션 맨 위의 드롭다운 목록에서 이전 버전 중 하나를 선택하는 것입니다. **최신 버전 표시** 또는 **버전 #N 표시**로 표시됩니다.

[이슈 392540](https://gitlab.com/gitlab-org/gitlab/-/issues/392540)은 이 동작의 개선을 추적합니다.
