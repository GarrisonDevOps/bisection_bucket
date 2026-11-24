---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 프로젝트 생성
description: 새로운 프로젝트 및 프로젝트 템플릿입니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

프로젝트를 생성하는 여러 가지 방법이 있습니다. 빈 프로젝트를 생성하거나, 내장된 템플릿 또는 사용자 정의 템플릿에서 프로젝트를 생성하거나, [`git push`로 프로젝트를 생성](../../topics/git/project.md)할 수 있습니다.

## 빈 프로젝트 생성 {#create-a-blank-project}

빈 프로젝트를 생성하려면:

1. 오른쪽 상단 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 그리고 **새 프로젝트/리포지토리**를 선택합니다.
1. **빈 프로젝트 생성**을 선택합니다.
1. 프로젝트 세부 정보를 입력합니다:
   1. **프로젝트 이름**: 프로젝트의 이름을 입력합니다. 자세한 내용은 [명명 규칙](../reserved_names.md#rules-for-usernames-project-and-group-names-and-slugs)을 참조하세요.
   1. **프로젝트 슬러그**: 프로젝트의 경로를 입력합니다. GitLab은 슬러그를 URL 경로로 사용합니다.
   1. **프로젝트 배포 대상 (옵션)**: 프로젝트를 특정 환경에 배포하려면 관련 배포 대상을 선택합니다.
   1. **공개 수준**: 적절한 공개 수준을 선택합니다. 사용자의 [보기 및 액세스 권한](../public_access.md)을 참조하세요.
   1. **README 파일을 포함하여 리포지토리 초기화**: 이 옵션을 선택하여 Git 리포지토리를 초기화하고 기본 브랜치를 생성한 후 이 프로젝트의 리포지토리 복제를 활성화합니다.
   1. **정적 애플리케이션 보안 테스트(SAST) 활성화**: 이 옵션을 선택하여 소스 코드에서 알려진 보안 취약점을 분석합니다.
   1. **비밀 탐지 활성화**: 이 옵션을 선택하여 소스 코드에서 비밀과 자격 증명을 분석하여 무단 액세스를 방지합니다.
1. **프로젝트 생성**을 선택합니다.

## 내장된 템플릿에서 프로젝트 생성 {#create-a-project-from-a-built-in-template}

내장된 템플릿은 새 프로젝트를 시작하는 데 도움이 되는 파일로 새 프로젝트를 채웁니다. 이러한 템플릿은 [`project-templates`](https://gitlab.com/gitlab-org/project-templates) 그리고 [`pages`](https://gitlab.com/pages) 그룹에서 제공됩니다. 누구나 내장된 프로젝트 템플릿에 기여할 수 있습니다.

관리자 및 그룹 소유자는 프로젝트를 생성할 때 [내장된 템플릿 가용성을 제어](../group/manage.md#control-built-in-project-templates)할 수 있습니다.

내장된 템플릿에서 프로젝트를 생성하려면:

1. 오른쪽 상단 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 그리고 **새 프로젝트/리포지토리**를 선택합니다.
1. **템플릿으로 부터 생성**을 선택합니다.
1. **내장된** 탭을 선택합니다.
1. 템플릿 목록에서:
   - 템플릿을 미리보려면 **미리보기**를 선택합니다.
   - 템플릿을 사용하려면 **템플릿 사용**을 선택합니다.
1. 프로젝트 세부 정보를 입력합니다:
   - **프로젝트 이름**: 프로젝트의 이름을 입력합니다.
   - **프로젝트 슬러그**: 프로젝트의 경로를 입력합니다. GitLab은 슬러그를 URL 경로로 사용합니다.
   - **프로젝트 설명 (옵션)** 프로젝트에 대한 설명을 입력합니다. 문자 제한은 500자입니다.
   - **공개 수준**: 적절한 공개 수준을 선택합니다. 사용자의 [보기 및 액세스 권한](../public_access.md)을 참조하세요.
1. **프로젝트 생성**을 선택합니다.

> [!note]
> 사용자가 템플릿에서 프로젝트를 생성하거나 [프로젝트를 가져오면](settings/import_export.md#import-a-project-and-its-data), 템플릿 또는 가져오기에서 원본 타임스탐프를 유지하는 가져온 항목의 작성자로 표시됩니다. 이로 인해 사용자 계정이 존재하기 전에 생성된 것처럼 항목이 표시될 수 있습니다.

가져온 객체는 `By <username> on <timestamp>`로 표시됩니다. GitLab 17.1 이전에는 레이블에 `(imported from GitLab)`가 접미사로 붙었습니다.

### HIPAA 감사 프로토콜 템플릿에서 프로젝트 생성 {#create-a-project-from-the-hipaa-audit-protocol-template}

HIPAA 감사 프로토콜 템플릿에는 미국 보건 및 인간 서비스부가 발행한 HIPAA 감사 프로토콜의 감사 조회에 대한 이슈가 포함되어 있습니다.

HIPAA 감사 프로토콜 템플릿에서 프로젝트를 생성하려면:

1. 오른쪽 상단 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 그리고 **새 프로젝트/리포지토리**를 선택합니다.
1. **템플릿으로 부터 생성**을 선택합니다.
1. **내장된** 탭을 선택합니다.
1. **HIPAA 감사 프로토콜** 템플릿을 찾습니다:
   - 템플릿을 미리보려면 **미리보기**를 선택합니다.
   - 템플릿을 사용하려면 **템플릿 사용**을 선택합니다.
1. 프로젝트 세부 정보를 입력합니다:
   - **프로젝트 이름**: 프로젝트의 이름을 입력합니다.
   - **프로젝트 슬러그**: 프로젝트의 경로를 입력합니다. GitLab은 슬러그를 URL 경로로 사용합니다.
   - **프로젝트 설명 (옵션)** 프로젝트에 대한 설명을 입력합니다. 문자 제한은 500자입니다.
   - **공개 수준**: 적절한 공개 수준을 선택합니다. 사용자의 [보기 및 액세스 권한](../public_access.md)을 참조하세요.
1. **프로젝트 생성**을 선택합니다.

## 사용자 정의 템플릿에서 프로젝트 생성 {#create-a-project-from-a-custom-template}

{{< history >}}

- 그룹 컨텍스트 외부에서 그룹 템플릿을 탐색하기 위한 그룹 선택기는 GitLab 18.11에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/590012)되었으며, [기능 플래그](../../administration/feature_flags/_index.md) `constrain_group_project_templates`로 명명되었습니다. 기본적으로 비활성화되었습니다.
- 그룹 컨텍스트 외부에서 그룹 템플릿을 탐색하기 위한 그룹 선택기는 GitLab 19.0에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/issues/586332)되었습니다. 기능 플래그 `constrain_group_project_templates`이 제거되었습니다.

{{< /history >}}

사용자 정의 프로젝트 템플릿은 [인스턴스](../../administration/project_templates.md) 및 [그룹](../group/custom_project_templates.md)에 사용할 수 있습니다.

사용자 정의 템플릿에서 프로젝트를 생성하려면:

1. 오른쪽 상단 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 그리고 **새 프로젝트/리포지토리**를 선택합니다.
1. **템플릿으로 부터 생성**을 선택합니다.
1. **인스턴스** 또는 **그룹** 탭을 선택합니다.
   - **그룹** 탭에서 그룹 컨텍스트에 있지 않고 그룹이 사전 선택되지 않은 경우 그룹 드롭다운 목록이 표시됩니다. 그룹을 선택하여 템플릿을 로드합니다.
1. 템플릿 목록에서:
   - 템플릿을 미리보려면 **미리보기**를 선택합니다.
   - 템플릿을 사용하려면 **템플릿 사용**을 선택합니다.
1. 프로젝트 세부 정보를 입력합니다:
   - **프로젝트 이름**: 프로젝트의 이름을 입력합니다.
   - **프로젝트 슬러그**: 프로젝트의 경로를 입력합니다. GitLab은 슬러그를 URL 경로로 사용합니다.
   - **프로젝트 설명 (옵션)** 프로젝트에 대한 설명을 입력합니다. 문자 제한은 500자입니다.
   - **공개 수준**: 적절한 공개 수준을 선택합니다. 사용자의 [보기 및 액세스 권한](../public_access.md)을 참조하세요.
1. **프로젝트 생성**을 선택합니다.

## SHA-256 해싱을 사용하는 프로젝트 생성 {#create-a-project-that-uses-sha-256-hashing}

{{< details >}}

- 상태:  실험적 기능

{{< /details >}}

{{< history >}}

- GitLab 16.7에서 `support_sha256_repositories`라는 [기능 플래그](../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/431864)되었습니다. 기본적으로 비활성화되었습니다. 이 기능은 [실험](../../policy/development_stages_support.md#experiment)입니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요. 이 기능은 테스트 가능하지만 프로덕션 사용은 준비되지 않았습니다.

프로젝트를 생성할 때만 프로젝트에 대해 SHA-256 해싱을 선택할 수 있습니다. Git은 나중에 SHA-256으로 마이그레이션하거나 SHA-1로 다시 마이그레이션하는 것을 지원하지 않습니다.

SHA-256 해싱을 사용하는 프로젝트를 생성하려면:

1. 오른쪽 상단 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 그리고 **새 프로젝트/리포지토리**를 선택합니다.
1. 프로젝트 세부 정보를 입력합니다:
   - **프로젝트 이름**: 프로젝트의 이름을 입력합니다.
   - **프로젝트 슬러그**: 프로젝트의 경로를 입력합니다. GitLab은 슬러그를 URL 경로로 사용합니다.
   - **프로젝트 설명 (옵션)** 프로젝트에 대한 설명을 입력합니다. 문자 제한은 500자입니다.
   - **공개 수준**: 적절한 공개 수준을 선택합니다. 사용자의 [보기 및 액세스 권한](../public_access.md)을 참조하세요.
1. **프로젝트 구성** 영역에서 **실험기능 설정**을 확장합니다.
1. **리포지토리 해싱 알고리즘으로 SHA-256 사용**을 선택합니다.
1. **프로젝트 생성**을 선택합니다.

### 왜 SHA-256인가? {#why-sha-256}

기본적으로 Git은 SHA-1 해싱 알고리즘을 사용하여 커밋, blob, 트리, 태그 같은 객체에 대해 40자 ID를 생성합니다. SHA-1 알고리즘은 [Google이 해시 충돌을 만들 수](https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html) 있을 때 안전하지 않은 것으로 입증되었습니다. Git 프로젝트는 Git이 객체를 저장하는 방식 때문에 아직 이러한 종류의 공격의 영향을 받지 않습니다.

SHA-256 리포지토리에서 알고리즘은 40자 ID 대신 64자 ID를 생성합니다. Git 프로젝트는 [실험 레이블을 제거](https://github.com/git/git/blob/master/Documentation/RelNotes/2.42.0.txt#L41-L45)할 때 SHA-256 기능을 안전하게 사용할 수 있다고 판단했습니다.

NIST 및 CISA [지침](https://csrc.nist.gov/projects/hash-functions/nist-policy-on-hash-functions)과 같은 연방 규정은 [FedRamp](https://www.fedramp.gov/)가 시행하며, 2030년까지 SHA-1 사용을 중단하고 가능한 경우 더 빨리 SHA-1에서 벗어나도록 권장하는 기한을 정했습니다.

## 관련 항목 {#related-topics}

- [`git push`로 프로젝트 생성](../../topics/git/project.md)
- [예약된 프로젝트 및 그룹 이름](../reserved_names.md)
- [프로젝트 및 그룹 이름 규칙](../reserved_names.md#rules-for-usernames-project-and-group-names-and-slugs)
- [프로젝트 관리](working_with_projects.md)
