---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 코드 드롭다운 목록의 사용자 지정 Git 클라이언트
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed
- 상태:  베타

{{< /details >}}

{{< history >}}

- GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/604390)되었으며 [플래그](../feature_flags/_index.md)는 `custom_code_dropdown_clients`입니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요.

사용자 지정 클라이언트를 프로젝트 페이지의 **다음으로 열기** 섹션의 **코드** 드롭다운 목록에 추가합니다. 그러면 사용자가 GitLab에서 기본적으로 나열하지 않는 Git 클라이언트에 리포지토리를 직접 복제할 수 있습니다.

## 사용자 지정 클라이언트 구성 {#configure-custom-clients}

전제 조건:

- 관리자여야 합니다.
- `custom_code_dropdown_clients` 기능 플래그를 활성화해야 합니다.

항목을 구성하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. **설정** > **리포지토리**를 선택합니다.
1. **일반**을 확장합니다.
1. **클라이언트 추가**를 선택합니다.
1. 필드를 완성하세요. 최소한 하나의 URL 템플릿을 입력합니다.
   - **이름 표시**: 드롭다운 목록에서 사용자에게 표시되는 레이블입니다. 번역되지 않습니다.
   - **SSH URL 템플릿**: 사용자가 **SSH**를 선택할 때 열리는 URL입니다.
   - **HTTPS URL 템플릿**: 사용자가 **HTTPS**를 선택할 때 열리는 URL입니다.
1. **추가**를 선택합니다.

항목을 편집하려면 옆에 있는 **클라이언트 편집** ({{< icon name="pencil" >}})을 선택하고 필드를 업데이트한 후 **저장**을 선택합니다.

항목을 삭제하려면 옆에 있는 **클라이언트 삭제** ({{< icon name="remove" >}})를 선택한 후 확인 대화 상자에서 **클라이언트 삭제**를 선택합니다.

최대 20개의 항목을 구성할 수 있습니다.

## URL 템플릿 {#url-templates}

각 URL 템플릿은 플레이스홀더 `{url}`를 정확히 한 번 포함해야 합니다. 코드 드롭다운 목록이 렌더링되면 GitLab은 플레이스홀더를 서버 측에서 프로젝트의 백분율로 인코딩된 복제 URL로 바꿉니다.

### 허용되는 URL 스키마 {#allowed-url-schemes}

통합하려는 클라이언트에서 예상하는 스키마를 입력합니다. 모든 URL 스키마가 허용되지만, 브라우저가 스크립트를 실행하거나 로컬 파일을 읽는 데 사용할 수 있는 다음과 같은 스키마는 제외됩니다:

- `javascript`
- `data`
- `vbscript`
- `file`
- `blob`
- `filesystem`
- `about`

항목을 선택하면 URL이 사용자의 운영 체제가 해당 스키마에 대해 등록한 애플리케이션으로 전달됩니다.

> [!note]
> GitLab은 해당 애플리케이션이 URL로 무엇을 하는지 확인할 수 없습니다. 신뢰할 수 있는 클라이언트만 추가합니다.

사용자의 운영 체제에 해당 스키마에 대해 등록된 애플리케이션이 없으면 브라우저는 링크를 열 수 없습니다.

### 예제 {#examples}

다음 항목들은 공급업체 문서에 대해 검증되었습니다.

항목을 사용자에게 게시하기 전에 통합 중인 클라이언트의 공식 문서에 대해 현재 URI 스키마를 항상 확인합니다.

| 이름 표시 | SSH URL 템플릿 | HTTPS URL 템플릿 | 소스 |
|---|---|---|---|
| VSCodium | `vscodium://vscode.git/clone?url={url}` | `vscodium://vscode.git/clone?url={url}` | [VSCodium prepare_vscode.sh](https://github.com/VSCodium/vscodium/blob/master/prepare_vscode.sh)는 `urlProtocol`를 `vscodium`으로 등록하며, 업스트림 VS Code `vscode.git/clone` 핸들러를 재사용합니다. |
| Tower | `gittower://openRepo/{url}` | `gittower://openRepo/{url}` | [Tower 문서 (macOS)](https://www.git-tower.com/help/guides/integration/url-scheme/mac), [Tower 문서 (Windows)](https://www.git-tower.com/help/guides/integration/url-scheme/windows) |
| Sourcetree, Fork | `sourcetree://cloneRepo?cloneUrl={url}` | `sourcetree://cloneRepo?cloneUrl={url}` | Fork는 동일한 스키마를 가로챕니다. |

일부 클라이언트는 단일 `{url}` 플레이스홀더 모델과 호환되지 않습니다. 예를 들어 GitKraken과 GitHub Desktop은 추가 리포지토리별 매개변수가 필요합니다. 기타 클라이언트(예: Zed 및 Working Copy)는 타사 문서에 나타나지만 공식 공급업체 URI 스키마 참조가 부족합니다. 그러한 항목을 추가하기 전에 공급업체에 확인합니다.
