---
stage: AI Coding
group: DAP Repository Flows
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Code Suggestions는 입력 시 AI를 사용하여 코드를 제안함으로써 GitLab에서 더 효율적으로 코드를 작성하도록 도와줍니다.
title: Code Suggestions
---

{{< details >}}

- 티어: [Free](../../../../subscriptions/gitlab_credits.md#for-the-free-tier), Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< collapsible title="모델 정보" >}}

- [기본 LLM](../../../gitlab_duo/model_selection.md#default-models)
- Amazon Q용 LLM: Amazon Q Developer
- [자체 호스팅 모델이 포함된 GitLab Duo](../../../../administration/gitlab_duo_self_hosted/_index.md)에서 사용 가능

{{< /collapsible >}}

{{< history >}}

- [변경](https://gitlab.com/gitlab-org/fulfillment/meta/-/issues/2031)됨 - 2024년 2월 15일에 GitLab Duo Pro 추가 기능이 필요하도록 변경되었습니다. 이전에는 이 기능이 GitLab Premium 및 Ultimate 구독에 포함되어 있었습니다.
- [변경](https://gitlab.com/gitlab-org/fulfillment/meta/-/issues/2031)됨 - 2024년 10월 17일부터 지원되는 모든 GitLab 버전에 대해 GitLab Duo Pro 또는 GitLab Duo Enterprise 추가 기능이 필요합니다.
- [Fireworks AI 호스팅 Qwen2.5 코드 완성 모델 지원 추가](https://gitlab.com/groups/gitlab-org/-/work_items/15850)됨 - GitLab 17.6에서 `fireworks_qwen_code_completion` 플래그로 추가되었습니다.
- [제거](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/187397)됨 - GitLab 17.11에서 Qwen2.5 코드 완성 모델에 대한 지원이 제거되었습니다.
- GitLab 17.11에서 기능 플래그 `use_fireworks_codestral_code_completion`를 통해 기본적으로 Fireworks 호스팅 `Codestral`을(를) 활성화했습니다.
- GitLab 18.0에 GitLab Duo Core를 포함하도록 변경되었습니다.
- GitLab 18.1에서 Fireworks 호스팅 `Codestral`을(를) 기본 모델로 활성화했습니다.
- [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/545489)됨 - GitLab 18.2에서 코드 생성의 기본 모델이 Claude Sonnet 4로 변경되었습니다.
- [제거](https://gitlab.com/gitlab-org/gitlab/-/issues/462750)됨 - GitLab 18.6에서 기능 플래그 `code_suggestions_context`가 제거되었습니다.
- GitLab 18.10부터 GitLab.com의 Free 티어에서 GitLab Credits를 사용하여 이용 가능합니다.
- GitLab Duo Core 사용자가 Code Suggestions에 액세스하는 방식이 변경되었습니다. 이제 GitLab 19.0부터 GitLab Duo Agent Platform의 일부로 사용 가능합니다.

{{< /history >}}

> [!note]
> Code Suggestions는 다음에 사용할 수 있습니다:
>
> - GitLab Duo Agent Platform입니다. 청구는 [사용량 기반](../../../../subscriptions/gitlab_credits.md)입니다.
> - GitLab Duo Pro 또는 Enterprise, GitLab Duo with Amazon Q입니다. 청구는 추가 기능에 따릅니다.

GitLab Duo Code Suggestions를 사용하여 생성 AI를 통해 개발 중에 코드 제안을 받으므로 더 효율적으로 코드를 작성합니다.

- <i class="fa-youtube-play" aria-hidden="true"></i> [클릭 투어 데모 보기](https://gitlab.navattic.com/code-suggestions)
  <!-- Video published on 2023-12-09 --> <!-- Demo published on 2024-02-01 -->
- <i class="fa-youtube-play" aria-hidden="true"></i> [개요 보기](https://youtu.be/ds7SG1wgcVM)

## 사전 요구 사항 {#prerequisites}

- [GitLab Duo Core가 활성화](../../../gitlab_duo/turn_on_off.md#turn-gitlab-duo-core-on-or-off)되어 있습니다.
- [Code Suggestions가 설정](set_up.md)되어 있습니다(IDE에서).
- [기본 GitLab Duo 네임스페이스](../../../profile/preferences.md#namespace-resolution-in-your-local-environment)가 설정되어 있거나 GitLab Duo 액세스가 있는 프로젝트를 열어두었습니다.

> [!note]
> GitLab Duo에는 GitLab 17.2 이상이 필요합니다. GitLab Duo Core 액세스 및 최고의 사용자 경험과 결과를 위해 [GitLab 18.0 이상으로 업그레이드](../../../../update/_index.md)하세요. 이전 버전은 계속 작동할 수 있지만 환경이 저하될 수 있습니다.

## Code Suggestions 사용 {#use-code-suggestions}

Code Suggestions를 사용하려면:

1. IDE에서 프로젝트를 엽니다.
1. 코드를 작성합니다. 입력하면 제안이 표시됩니다. Code Suggestions는 커서 위치에 따라 코드 스니펫을 제공하거나 현재 줄을 완성합니다.

1. 자연어로 요구사항을 설명합니다. Code Suggestions는 제공된 컨텍스트를 기반으로 함수 및 코드 스니펫을 생성합니다.

1. 제안을 받으면 다음 중 하나를 수행할 수 있습니다:
   - 제안을 수락하려면 <kbd>Tab</kbd>을 누릅니다.
   - 부분 제안을 수락하려면 <kbd>Control</kbd>+<kbd>오른쪽 화살표</kbd> 또는 <kbd>Command</kbd>+<kbd>오른쪽 화살표</kbd>을 누릅니다.
   - 제안을 거부하려면 <kbd>Esc</kbd>를 누릅니다. Neovim에서 <kbd>Control</kbd>+<kbd>E</kbd>를 눌러 메뉴를 종료합니다.
   - 제안을 무시하려면 평소처럼 입력을 계속합니다.

## 여러 코드 제안 보기 {#view-multiple-code-suggestions}

{{< history >}}

- GitLab 17.1에서 [도입](https://gitlab.com/gitlab-org/gitlab-vscode-extension/-/issues/1325)되었습니다.

{{< /history >}}

VS Code의 코드 완성 제안에 대해 여러 제안 옵션을 사용할 수 있습니다. 사용 가능한 모든 제안을 보려면:

1. 코드 완성 제안 위에 마우스를 올립니다.
1. 대안을 스크롤합니다. 다음 중 하나를 선택합니다.
   - 키보드 단축키를 사용합니다:
     - Mac에서 <kbd>Option</kbd>+<kbd>[</kbd>을 눌러 이전 제안을 보고 <kbd>Option</kbd>+<kbd>]</kbd>을 눌러 다음 제안을 봅니다.
     - Linux 및 Windows에서 <kbd>Alt</kbd>+<kbd>[</kbd>을 눌러 이전 제안을 보고 <kbd>Alt</kbd>+<kbd>]</kbd>을 눌러 다음 제안을 봅니다.
   - 표시된 대화 상자에서 오른쪽 또는 왼쪽 화살표를 선택하여 다음 또는 이전 옵션을 봅니다.
1. <kbd>Tab</kbd>을 눌러 선호하는 제안을 적용합니다.

## 코드 완성 및 생성 {#code-completion-and-generation}

Code Suggestions는 코드 완성 및 코드 생성을 사용합니다:

|  | 코드 완성 | 코드 생성 |
| :---- | :---- | :---- |
| 목적 | 현재 코드 줄을 완성하기 위한 제안을 제공합니다.  | 자연어 주석을 기반으로 새 코드를 생성합니다. |
| 트리거 | 입력할 때 트리거되며 일반적으로 짧은 지연이 있습니다.  | 특정 키워드를 포함하는 주석을 작성한 후 <kbd>Enter</kbd>를 누를 때 트리거됩니다. |
| 범위 | 현재 줄 또는 작은 코드 블록으로 제한됩니다.  | 컨텍스트를 기반으로 전체 메서드, 함수 또는 클래스를 생성할 수 있습니다. |
| 정확도 | 작은 작업 및 짧은 코드 블록에 대해 더 정확합니다.  | 더 큰 대규모 언어 모델(LLM)이 사용되고, 요청에 추가 컨텍스트(예: 프로젝트에서 사용하는 라이브러리)가 전송되며, 지시사항이 LLM으로 전달되기 때문에 복잡한 작업 및 큰 코드 블록에 대해 더 정확합니다. |
| 사용 방법 | 코드 완성은 입력 중인 줄에 자동으로 완성을 제안합니다. | 주석을 작성하고 <kbd>Enter</kbd>를 누르거나 빈 함수 또는 메서드를 입력합니다. |
| 사용 시기 | 코드 완성을 사용하여 한두 줄의 코드를 빠르게 완성합니다. | 더 복잡한 작업, 더 큰 코드베이스, 자연어 설명을 기반으로 처음부터 새 코드를 작성하려는 경우 또는 편집 중인 파일에 5줄 미만의 코드가 있을 때 코드 생성을 사용합니다. |

Code Suggestions는 항상 이 두 기능을 모두 사용합니다. 코드 생성만 사용하거나 코드 완성만 사용할 수 없습니다. 또한 따로 비활성화할 수 없습니다.

<i class="fa-youtube-play" aria-hidden="true"></i> [코드 완성 대 코드 생성 비교 데모 보기](https://www.youtube.com/watch?v=9dsyqMt9yg4)
<!-- Video published on 2024-09-26 -->

### 코드 생성을 위한 모범 사례 {#best-practices-for-code-generation}

코드 생성에서 최고의 결과를 얻으려면:

- 간결하면서도 가능한 한 구체적입니다.
- 생성하려는 결과(예: 함수)를 명시하고 달성하려는 작업에 대한 세부 정보를 제공합니다.
- 사용하려는 프레임워크나 라이브러리와 같은 추가 정보를 추가합니다.
- 각 주석 뒤에 공백이나 새 줄을 추가합니다. 이 공백은 코드 생성기에 지시사항을 완료했음을 알립니다.
- [Code Suggestions에서 사용 가능한 컨텍스트](context.md)를 검토하고 조정합니다.

예를 들어, 특정 요구사항이 있는 Python 웹 서비스를 만들려면 다음과 같이 작성할 수 있습니다:

```plaintext
# Create a web service using Tornado that allows a user to sign in, run a security scan, and review the scan results.
# Each action (sign in, run a scan, and review results) should be its own resource in the web service
...
```

AI는 비결정적이므로 동일한 입력으로 매번 같은 제안을 얻지 못할 수 있습니다. 품질 있는 코드를 생성하려면 명확하고 설명적이고 구체적인 작업을 작성합니다.

사용 사례 및 모범 사례는 [GitLab Duo 예제 설명서](../../../gitlab_duo/use_cases.md)를 따릅니다.

## 성능 {#performance}

Code Suggestions의 기본 응답 시간과 스트리밍, 프롬프트 캐싱 및 연결 구성 옵션에 대해 알아봅니다.

### 응답 시간 {#response-time}

Code Suggestions는 생성형 AI 모델로 구동됩니다.

- 코드 완성의 경우 제안은 일반적으로 짧은 지연 시간으로 1초 미만이 걸립니다.
- 코드 생성의 경우 알고리즘이나 큰 코드 블록은 생성하는 데 5초 이상이 걸릴 수 있습니다.

개인 액세스 토큰을 사용하면 GitLab.com 또는 GitLab 인스턴스에 대한 안전한 API 연결을 사용할 수 있습니다. 이 API 연결은 IDE/편집기의 컨텍스트 윈도우를 [GitLab AI Gateway](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist)에 안전하게 전송하며, 이는 GitLab 호스팅 서비스입니다. 게이트웨이가 대규모 언어 모델 API를 호출한 후 생성된 제안이 IDE/편집기로 다시 전송됩니다.

### 스트리밍 {#streaming}

코드 생성 응답은 VS Code, JetBrains IDE, Visual Studio 및 Eclipse에서 스트리밍되므로 생성된 코드가 더 빨리 표시됩니다. Neovim에서 스트리밍에는 실험적 [ghost text 기능](../../../../editor_extensions/neovim/setup.md#configure-the-extension)이 필요합니다.

스트리밍은 코드 완성에 대해 활성화되지 않습니다.

### 프롬프트 캐싱 {#prompt-caching}

{{< history >}}

- GitLab 18.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/535651)되었습니다.

{{< /history >}}

프롬프트 캐싱은 Code Suggestions 지연 시간을 개선하기 위해 모든 Fireworks 호스팅 모델에서 기본적으로 활성화됩니다.

프롬프트 캐싱이 활성화되면 코드 완성 프롬프트 데이터가 모델 공급자가 메모리에 임시로 저장합니다.

프롬프트 캐싱은 캐시된 프롬프트 및 입력 데이터의 재처리를 방지하여 지연 시간을 크게 개선합니다. 캐시된 데이터는 영구 스토리지에 기록되지 않습니다.

[프롬프트 캐싱을 끌](../../../gitlab_duo/data_usage.md#turn-off-prompt-caching) 수 있습니다.

- GitLab.com:  최상위 그룹의 경우.
- GitLab Self-Managed:  인스턴스의 경우.

이 설정은 모든 GitLab Duo Agent Platform 기능에 적용됩니다.

### 직접 및 간접 연결 {#direct-and-indirect-connections}

{{< history >}}

- `code_suggestions_direct_access`라는 이름의 [기능 플래그](../../../../administration/feature_flags/_index.md)와 함께 GitLab 17.2에 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/462791)되었습니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

기본적으로 코드 완성 요청은 지연 시간을 최소화하기 위해 IDE에서 AI Gateway로 직접 전송됩니다. 이 직접 연결이 작동하려면 IDE가 `https://cloud.gitlab.com:443`에 연결할 수 있어야 합니다. 이것이 불가능한 경우(예: 네트워크 제한으로 인해) 모든 사용자에 대해 직접 연결을 비활성화할 수 있습니다. 이렇게 하면 코드 완성 요청이 GitLab Self-Managed 인스턴스를 통해 간접적으로 전송되며, 이는 차례로 AI Gateway에 요청을 전송합니다. 이로 인해 요청의 지연 시간이 더 길어질 수 있습니다.

#### 직접 또는 간접 연결 구성 {#configure-direct-or-indirect-connections}

사전 요구 사항:

- GitLab Self-Managed 인스턴스의 관리자여야 합니다.

{{< tabs >}}

{{< tab title="17.4 이상" >}}

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **GitLab Duo 기능**을 확장합니다.
1. **연결 방법** 아래에서 옵션을 선택합니다:
   - 코드 완성 요청에 대한 지연 시간을 최소화하려면 **직접 연결**을 선택합니다.
   - 모든 사용자에 대해 직접 연결을 비활성화하려면 **자체 관리 GitLab을 통한 간접 연결**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

{{< /tab >}}

{{< tab title="17.3 이전" >}}

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **AI-네이티브 기능**을 확장합니다.
1. 옵션을 선택합니다:
   - 코드 완성 요청에 대한 직접 연결을 활성화하고 지연 시간을 최소화하려면 **Code Suggestions에 대한 직접 연결 비활성화** 체크박스를 선택 해제합니다.
   - 직접 연결을 비활성화하려면 **Code Suggestions에 대한 직접 연결 비활성화** 체크박스를 선택합니다.

{{< /tab >}}

{{< /tabs >}}

## 제한사항 {#limitations}

### 파일 내용 잘림 {#truncation-of-file-content}

LLM 제한 및 성능상의 이유로 현재 열려 있는 파일의 내용이 잘립니다:

- 코드 완성의 경우: 32,000개 토큰(대략 128,000자)으로.
- 코드 생성의 경우: 80,000개 토큰(대략 320,000자)으로.

커서 위의 내용이 커서 아래의 내용보다 우선합니다. 커서 위의 내용은 왼쪽에서 잘리고 커서 아래의 내용은 오른쪽에서 잘립니다. 이 숫자는 Code Suggestions의 최대 입력 컨텍스트 크기를 나타냅니다.

코드 생성 제한 증가에 대한 지원이 [이슈 585841](https://gitlab.com/gitlab-org/gitlab/-/issues/585841)에서 제안되었습니다.

### 출력 길이 {#output-length}

LLM 제한 및 성능상의 이유로 Code Suggestions의 출력은 제한됩니다:

- 코드 완성의 경우: 64개 토큰(대략 256자)으로.
- 코드 생성의 경우: 2048개 토큰(대략 7168자)으로.

### 결과의 정확도 {#accuracy-of-results}

생성된 전체 콘텐츠의 정확도를 계속 개선하고 있습니다. 그러나 Code Suggestions는 다음과 같은 제안을 생성할 수 있습니다:

- 관련 없는.
- 불완전한.
- 파이프라인 실패를 초래할 가능성이 있습니다.
- 잠재적으로 안전하지 않습니다.
- 모욕적이거나 무신경한.

Code Suggestions를 사용할 때 코드 검토 모범 사례가 여전히 적용됩니다.
