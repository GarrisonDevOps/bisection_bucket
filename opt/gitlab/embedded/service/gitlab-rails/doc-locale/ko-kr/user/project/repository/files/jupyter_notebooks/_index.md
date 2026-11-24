---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLab 프로젝트는 Jupyter Notebook 파일을 원본 파일 대신 깨끗하고 읽기 쉬운 파일로 표시합니다.
title: Jupyter Notebook 파일
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[Jupyter Notebook](https://jupyter.org/) (이전의 IPython Notebook) 파일은 많은 분야에서 대화형 컴퓨팅에 사용됩니다. 사용자 세션의 완전한 기록을 포함하며 다음을 포함합니다:

- 코드.
- 서술형 텍스트.
- 방정식.
- 리치 출력.

Jupyter Notebook을 `.ipynb` 확장자로 리포지토리에 추가하면 보는 시점에 HTML로 렌더링됩니다:

![Jupyter Notebook 리치 출력](img/jupyter_notebook_v17_10.png)

JavaScript 플롯을 포함한 대화형 기능은 GitLab에서 볼 때 작동하지 않습니다.

## 더 깨끗한 diff와 원본 diff {#cleaner-diffs-and-raw-diffs}

커밋이 Jupyter Notebook 파일의 변경 사항을 포함할 때 GitLab은:

- 기계가 읽을 수 있는 `.ipynb` 파일을 인간이 읽을 수 있는 Markdown 파일로 변환합니다.
- 구문 강조를 포함하는 더 깨끗한 버전의 diff를 표시합니다.
- 커밋 및 비교 페이지에서 원본 및 렌더링된 diff 간 전환을 활성화합니다. (머지 리퀘스트 페이지에서는 사용할 수 없습니다.)
- diff의 이미지를 렌더링합니다.

코드 제안은 `.ipynb` 파일에 대한 diff 및 머지 리퀘스트에서 사용할 수 없습니다.

더 깨끗한 노트북 diff는 노트북이 너무 클 때 생성되지 않습니다.

## Jupyter Git 통합 {#jupyter-git-integration}

Jupyter는 인증된 사용자를 대신하여 리포지토리 액세스를 사용하여 OAuth 애플리케이션으로 구성할 수 있습니다. 구성 예는 [런북](../../../clusters/runbooks/_index.md)을 참조하세요.
