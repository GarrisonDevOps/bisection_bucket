---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 구문 강조는 GitLab 프로젝트의 파일을 읽고 파일에 포함된 내용을 식별하는 데 도움이 됩니다.
title: 구문 강조
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab은 두 가지 상호 보완적인 시스템을 통해 파일에 대한 구문 강조를 제공합니다:

- [Rouge](https://rubygems.org/gems/rouge) (Ruby gem): GitLab 서버에서 파일을 처리하는 서버 측 강조입니다. 다음을 위해 사용됩니다:
  - 리포지토리 파일 보기
  - 머지 리퀘스트 diff
  - 커밋 diff
  - 비교 보기
  - Blame 보기
- [Highlight.js](https://github.com/highlightjs/highlight.js/): 브라우저에서 실행되는 클라이언트 측 강조입니다. 지원되는 언어에 대해 브라우저에서 리포지토리 파일을 보는 데 사용됩니다.

여기의 경로는 Git에서 [`.gitattributes` 인터페이스](https://git-scm.com/docs/gitattributes)를 사용합니다.

> [!note]
> [Web IDE](../../web_ide/_index.md)와 [snippets](../../../snippets.md)는 텍스트 편집을 위해 [Monaco Editor](https://microsoft.github.io/monaco-editor/)를 사용하며, 구문 강조를 위해 내부적으로 [Monarch library](https://microsoft.github.io/monaco-editor/monarch.html)를 사용합니다.

## 파일 형식에 대한 구문 강조 재정의 {#override-syntax-highlighting-for-a-file-type}

> [!note]
> Web IDE는 `.gitattributes` 파일을 지원하지 않습니다. 자세한 내용은 [에픽 18651](https://gitlab.com/groups/gitlab-org/-/work_items/18651)을 참조하세요.

파일 형식에 대한 구문 강조를 재정의하려면:

1. `.gitattributes` 파일이 프로젝트의 루트 디렉토리에 없으면 이 이름의 빈 파일을 만듭니다.
1. 수정하려는 각 파일 형식에 대해 `.gitattributes` 파일에 줄을 추가하여 파일 확장자와 원하는 강조 언어를 선언합니다:

   ```conf
   # This extension typically receives Perl syntax highlighting. If you
   # also use Prolog, you can override highlighting for this file extension:
   *.pl gitlab-language=prolog
   ```

1. 변경 사항을 기본 브랜치에 커밋, 푸시 및 병합합니다.

변경 사항이 [기본 브랜치](../branches/default.md)에 병합된 후, 프로젝트의 모든 `*.pl` 파일이 선호하는 언어로 강조됩니다.

Common Gateway Interface (CGI) 옵션으로 강조를 확장할 수도 있습니다. 예를 들면:

``` conf
# JSON file with .erb in it
/my-cool-file gitlab-language=erb?parent=json

# An entire file of highlighting errors!
/other-file gitlab-language=text?token=Error
```

## 파일 형식에 대한 구문 강조 비활성화 {#disable-syntax-highlighting-for-a-file-type}

파일 형식에 대한 강조를 완전히 비활성화하려면 파일 형식에 대한 강조를 재정의하는 지침을 따르고 `gitlab-language=text`을 사용합니다:

```conf
# Disable syntax highlighting for this file type
*.module gitlab-language=text
```

## 강조에 대한 최대 파일 크기 구성 {#configure-maximum-file-size-for-highlighting}

다음 파일 크기 제한이 구문 강조 도구에 적용됩니다:

- Rouge (서버 측): 기본적으로 512 KB (구성 가능)
  - 이 제한보다 큰 파일은 구문 강조 없이 일반 텍스트로 렌더링됩니다.
- Highlight.js (클라이언트 측): 2 MB (구성 불가)
  - 언어가 지원되지 않으면 Rouge 강조로 대체됩니다.
  - 이 제한보다 큰 파일은 프런트엔드에서 강조할 수 없으며 원본 콘텐츠로 확인해야 합니다.

Rouge 강조 제한을 변경하려면:

1. 프로젝트의 [`gitlab.yml`](https://gitlab.com/gitlab-org/gitlab-foss/blob/master/config/gitlab.yml.example) 구성 파일을 엽니다.

1. 이 섹션을 추가하여 `maximum_text_highlight_size_kilobytes`을 원하는 값으로 바꿉니다.

   ```yaml
   gitlab:
     extra:
       ## Maximum file size for syntax highlighting
       ## https://docs.gitlab.com/user/project/repository/files/highlighting/#configure-maximum-file-size-for-highlighting
       maximum_text_highlight_size_kilobytes: 512
   ```

1. 변경 사항을 기본 브랜치에 커밋, 푸시 및 병합합니다.
