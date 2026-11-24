---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 파일의 코드 설명
---

{{< details >}}

- 티어: Premium, Ultimate
- 추가 기능: GitLab Duo Pro 또는 Enterprise, GitLab Duo with Amazon Q
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< collapsible title="모델 정보" >}}

- [기본 LLM](../../gitlab_duo/model_selection.md#default-models)
- Amazon Q용 LLM: Amazon Q Developer
- [자체 호스팅 모델이 포함된 GitLab Duo](../../../administration/gitlab_duo_self_hosted/_index.md)에서 사용 가능

{{< /collapsible >}}

{{< history >}}

- GitLab 16.8에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/429915)합니다.
- GitLab 17.6 이상에서 GitLab Duo 추가 기능이 필요하도록 변경되었습니다.
- GitLab 18.6에서 기본 LLM을 Claude Sonnet 4.5로 [업데이트](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/issues/1541)했습니다.

{{< /history >}}

다른 사람이 작성한 코드를 이해하기 위해 많은 시간을 보내거나 익숙하지 않은 언어로 작성된 코드를 이해하는 데 어려움을 겪는 경우 GitLab Duo에 코드 설명을 요청할 수 있습니다.

사전 요구 사항:

- 최소한 [실험 및 베타 기능 설정](../../gitlab_duo/turn_on_off.md#turn-on-beta-and-experimental-features)이 활성화된 그룹에 속해야 합니다.
- 프로젝트를 볼 수 있는 액세스 권한이 있어야 합니다.

파일의 코드를 설명하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 프로젝트에서 코드가 포함된 파일을 선택합니다.
1. 설명하려는 라인을 선택합니다.
1. 왼쪽에서 물음표 ({{< icon name="question" >}})를 선택하세요. 선택 항목의 첫 번째 줄까지 스크롤하여 이를 봐야 할 수도 있습니다.

   ![선택된 줄과 코드를 설명하는 데 사용할 수 있는 물음표 아이콘을 표시하는 파일 뷰입니다.](img/explain_code_v17_1.png)

GitLab Duo Chat은 코드를 설명합니다. 설명이 생성되는 데 잠깐 시간이 걸릴 수 있습니다.

원하는 경우 설명의 품질에 대한 의견을 제공할 수 있습니다.

대규모 언어 모델이 정확한 결과를 생성한다는 보장은 할 수 없습니다. 설명을 주의해서 사용하세요.

다음에서도 코드를 설명할 수 있습니다.

- [머지 리퀘스트](../merge_requests/changes.md#explain-code-in-a-merge-request).
- [IDE](../../gitlab_duo_chat/examples.md#explain-selected-code).
