---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "GitLab 프로젝트의 사용자 지정 Git 속성을 정의하여 파일 처리, 표시, 잠금 및 저장소 옵션을 설정합니다."
title: Git 속성
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab은 리포지토리의 루트 디렉터리에 있는 `.gitattributes` 파일에 사용자 지정 Git 속성을 정의하는 것을 지원합니다. `.gitattributes` 파일을 사용하여 다음과 같은 파일 처리 및 표시 변경 사항을 선언합니다:

- diff에서 [생성된 파일 축소](../../merge_requests/changes.md#collapse-generated-files)하기
- [사용자 지정 병합 드라이버](#custom-merge-drivers) 만들기
- [단독 잠금 파일](../../file_lock.md)을 만들어 파일을 읽기 전용으로 표시합니다.
- diff에서 [구문 강조 표시](highlighting.md) 변경
- [Git LFS](../../../../topics/git/lfs/_index.md)를 사용하여 이진 파일 처리 선언
- [리포지토리에서 사용하는 언어](../_index.md#add-repository-languages) 선언

## 인코딩 요구 사항 {#encoding-requirements}

`.gitattributes` 파일은 UTF-8로 인코딩되어야 하며 바이트 순서 표시를 포함하면 안 됩니다. 다른 인코딩을 사용하면 파일의 내용이 무시됩니다.

## 혼합 파일 인코딩 지원 {#support-for-mixed-file-encodings}

GitLab은 파일의 인코딩을 자동으로 감지하려고 시도하지만, 감지기가 다른 유형(예: `ISO-8859-1`)을 확신하지 않으면 UTF-8을 기본값으로 사용합니다. 잘못된 인코딩 감지로 인해 일부 문자(예: non-UTF-8 인코딩의 악센트 문자)가 텍스트에 표시되지 않을 수 있습니다.

Git은 이 상황을 처리하기 위한 기본 제공 지원을 제공하며 리포지토리 자체에 대해 지정된 인코딩과 UTF-8 간에 파일을 자동으로 변환합니다. `.gitattributes` 파일에서 `working-tree-encoding` 속성을 사용하여 혼합 파일 인코딩 지원을 구성합니다.

예:

```plaintext
*.xhtml text working-tree-encoding=ISO-8859-1
```

이 예제 구성을 사용하면 Git은 리포지토리의 모든 `.xhtml` 파일을 로컬 트리에서 ISO-8859-1 인코딩으로 유지하지만, 리포지토리에 커밋할 때 UTF-8로 또는 UTF-8에서 변환합니다. GitLab은 올바르게 인코딩된 UTF-8만 보므로 파일을 정확하게 렌더링합니다.

기존 리포지토리에 이 구성을 적용하는 경우, 로컬 복사본은 올바른 인코딩을 가지고 있지만 리포지토리는 그렇지 않으면 파일을 터치하고 다시 커밋해야 할 수 있습니다. `git add --renormalize .`을(를) 실행하여 전체 리포지토리에 대해 이를 수행할 수 있습니다.

자세한 내용은 [working-tree-encoding](https://git-scm.com/docs/gitattributes#_working_tree_encoding)을 참조하세요.

## 구문 강조 표시 {#syntax-highlighting}

`.gitattributes` 파일을 사용하여 파일 및 diff를 구문 강조할 때 사용할 언어를 정의할 수 있습니다. 자세한 내용은 [구문 강조 표시](highlighting.md)를 참조하세요.

## 사용자 지정 병합 드라이버 {#custom-merge-drivers}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab Self-Managed 관리자는 GitLab 구성 파일에서 [사용자 지정 병합 드라이버](https://git-scm.com/docs/gitattributes#_defining_a_custom_merge_driver)를 정의한 다음, Git `.gitattributes` 파일에서 사용자 지정 병합 드라이버를 사용할 수 있습니다. 사용자 지정 병합 드라이버는 GitLab.com에서 지원되지 않습니다.

사용자 지정 병합 드라이버는 병합 충돌 해결에 대한 고급 제어를 제공하는 Git 기능입니다. 사용자 지정 병합 드라이버는 비자명적인 [머지 충돌](../../merge_requests/conflicts.md)의 경우에만 호출되므로, 일부 파일이 병합되지 않도록 하는 신뢰할 수 있는 방법은 아닙니다.

### 사용자 지정 병합 드라이버 구성 {#configure-a-custom-merge-driver}

다음 예제는 GitLab에서 사용자 지정 병합 드라이버를 정의하고 사용하는 방법을 보여줍니다.

사용자 지정 병합 드라이버를 구성하는 방법은 설치 유형에 따라 다릅니다.

{{< tabs >}}

{{< tab title="Linux 패키지(Omnibus)" >}}

1. `/etc/gitlab/gitlab.rb`을(를) 편집합니다.
1. 다음과 유사한 구성을 추가합니다:

   ```ruby
   gitaly['configuration'] = {
     # ...
     git: {
       # ...
       config: [
         # ...
         { key: "merge.foo.driver", value: "true" },
       ],
     },
   }
   ```

{{< /tab >}}

{{< tab title="Self-compiled(source)" >}}

1. `gitaly.toml`을(를) 편집합니다.
1. 다음과 유사한 구성을 추가합니다:

   ```toml
   [[git.config]]
   key = "merge.foo.driver"
   value = "true"
   ```

{{< /tab >}}

{{< /tabs >}}

이 예제에서는 병합 중에 Git이 `driver` 값을 실행할 명령으로 사용합니다. 예제에서 [`true`](https://man7.org/linux/man-pages/man1/true.1.html)를 인수 없이 사용하므로 항상 0이 아닌 반환 코드를 반환합니다. 이는 `.gitattributes`에 지정된 파일의 경우 병합이 아무것도 수행하지 않음을 의미합니다.

자신의 병합 드라이버를 사용하려면 `driver`의 값을 바꿔 실행 파일을 가리키도록 합니다. 이 명령이 호출되는 방법에 대한 자세한 내용은 [사용자 지정 병합 드라이버](https://git-scm.com/docs/gitattributes#_defining_a_custom_merge_driver)에 대한 Git 설명서를 참조하세요.

### `.gitattributes`을(를) 사용하여 사용자 지정 병합 드라이버가 적용되는 파일 설정 {#use-gitattributes-to-set-files-custom-merge-driver-applies-to}

`.gitattributes` 파일에서 사용자 지정 병합 드라이버와 함께 사용할 파일의 경로를 설정할 수 있습니다. 예를 들어:

```plaintext
config/* merge=foo
```

이 경우, `config/` 폴더 아래의 모든 파일은 GitLab 구성에서 정의한 `foo`라는 사용자 지정 병합 드라이버를 사용합니다.

## 리소스 {#resources}

- [Git 속성](https://git-scm.com/docs/gitattributes)에 대한 공식 Git 설명서
