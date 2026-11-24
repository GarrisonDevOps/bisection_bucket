---
stage: Agent Foundations
group: Agent Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "워크플로우, 코딩 표준, 프로젝트 요구 사항에 맞게 GitLab Duo Agent Platform 동작을 사용자 지정합니다."
title: GitLab Duo Agent Platform 사용자 지정
---

Agent Platform을 워크플로우, 코딩 표준 또는 프로젝트 요구 사항에 맞게 사용자 지정할 수 있습니다.

## 사용자 지정 옵션 {#customization-options}

| 메서드 | AI 기능[^support-varies-where] | 사용 사례 | 지원 항목 |
|--------|--------------------------|-----------|--------------|
| [사용자 지정 규칙 사용](custom_rules.md)하여 지침을 제공합니다. | \- GitLab Duo Chat<br>\- 에이전트<br>\- 플로우(Code Review 플로우 제외) | \- 개인 선호도를 적용합니다.<br>\- 팀 표준을 적용합니다. | \- GitLab UI<br>\- 편집기 확장<br>\- GitLab Duo CLI |
| [AGENTS.md 파일 생성](agents_md.md)하여 지침을 제공합니다. | \- GitLab Duo Chat<br>\- 플로우(Code Review 플로우 제외) | \- 프로젝트별 컨텍스트를 고려합니다.<br>\- 모노레포를 구성합니다.<br>\- 디렉터리별 규칙을 적용합니다. | \- GitLab UI<br>\- 편집기 확장<br>\- GitLab Duo CLI<br>\- GitLab이 아닌 AI 코딩 도구 |
| [병합 요청 검토 지침 생성](review_instructions.md)하여 프로젝트에서 일관되고 구체적인 코드 검토 표준을 보장합니다. | \- Code Review 플로우 | 적용:<br>\- 언어별 검토 규칙.<br>\- 보안 표준.<br>\- 코드 품질 요구 사항.<br>\- 파일별 지침. | \- GitLab UI |
| [에이전트 스킬 생성](agent_skills.md)하여 스킬을 제공합니다. | \- GitLab Duo Chat<br>\- 플로우(Code Review 플로우 제외) | \- 공유 가능한 스킬 제공<br>\- 사용자 지정 슬래시 명령 추가 | \- GitLab UI<br>\- 편집기 확장<br>\- GitLab Duo CLI<br>\- GitLab이 아닌 AI 코딩 도구 |

[^support-varies-where]: 지원 범위는 해당 기능을 사용하는 위치에 따라 다릅니다. 자세한 내용은 각 사용자 지정 방법에 대한 설명서를 참조하세요.

## 모범 사례 {#best-practices}

에이전트 플랫폼을 사용자 지정할 때 다음 모범 사례를 적용하세요:

- 필요에 따라 최소한의 명확하고 간단한 지침으로 시작하고 더 추가합니다. 지침 파일을 최대한 짧게 유지합니다.
- 지침이 구체적이고 실행 가능한지 확인합니다. 필요한 경우 예제를 제공합니다.
- 사용 사례와 일치하는 방법을 선택합니다.
- 여러 방법을 조합하여 GitLab Duo의 동작을 맞춤화하고 제어합니다.
- 여러 방법을 사용하는 경우 프로젝트에 다음 파일 구조를 고려하세요:

  ```plaintext
  Project root directory
  |─ AGENTS.md                         # Applies to multiple Duo features
  |- skills/<skill-name>/
     |─ SKILL.md                       # Applies to multiple Duo features
  |─ .gitlab/duo/
     |─ chat-rules.md                  # Custom Chat-specific rules
     |─ mr-review-instructions.yaml    # Custom code review standards
     |─ ...                            # Other configuration as needed
  ```

  `.gitlab/duo/` 폴더에 [사용자 지정 플로우 정의](../flows/custom.md) 또는 [MCP 서버 구성](../../model_context_protocol/mcp_server.md) 파일과 같은 다른 구성 파일을 포함할 수 있습니다.
- 특정 지침이 존재하는 이유를 설명하기 위해 주석에 선택 사항을 문서화합니다.
- [코드 소유자](../../project/codeowners/_index.md)를 사용하여 사용자 지정 파일을 보호하고 변경 사항을 관리합니다.

## 관련 항목 {#related-topics}

- [GitLab Duo CLI용 훅](../../gitlab_duo_cli/customize.md#hooks)
