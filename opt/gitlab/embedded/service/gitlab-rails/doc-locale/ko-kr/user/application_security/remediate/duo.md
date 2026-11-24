---
stage: Security Risk Management
group: Security Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: AI로 취약성 해결
---

{{< details >}}

- 티어: Ultimate
- 추가 기능: GitLab Duo Enterprise, GitLab Duo with Amazon Q
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< collapsible title="모델 정보" >}}

- [기본 LLM](../../gitlab_duo/model_selection.md#default-models)
- Amazon Q용 LLM: Amazon Q Developer
- [GitLab Duo 자체 호스팅 모델](../../../administration/gitlab_duo_self_hosted/_index.md)에서 사용 가능: 예

{{< /collapsible >}}

GitLab Duo 취약성 해결을 통해 보안 취약성을 자동으로 해결할 수 있습니다.

<i class="fa fa-youtube-play youtube" aria-hidden="true"></i> [개요 보기](https://www.youtube.com/watch?v=VJmsw_C125E&list=PLFGfElNsQthZGazU1ZdfDpegu0HflunXW)

자세한 내용은 [모든 GitLab Duo 기능을 활성화하는 방법](../../gitlab_duo/turn_on_off.md)을 참조하세요.

## AI 지원을 책임감 있게 사용 {#use-ai-assistance-responsibly}

모든 AI 기반 시스템과 마찬가지로, 대규모 언어 모델이 항상 올바른 결과를 생성한다고 보장할 수 없습니다. 병합하기 전에 항상 제안된 변경 사항을 검토해야 합니다. 검토할 때 다음을 확인하세요.

- 애플리케이션의 기존 기능이 보존됩니다.
- 취약성이 조직의 기준에 따라 해결됩니다.

## 취약성 해결 방법을 지원하는 취약성 {#supported-vulnerabilities-for-vulnerability-resolution}

제안된 해결 방법의 품질을 보장하기 위해 취약성 해결 방법은 특정 취약성 집합에 대해 사용할 수 있습니다. 시스템은 취약성의 Common Weakness Enumeration(CWE) 식별자를 기반으로 취약성 해결 방법을 제공할지 여부를 결정합니다.

현재의 취약성 집합은 자동화된 시스템과 보안 전문가의 테스트를 기반으로 선택되었습니다. 더 많은 유형의 취약성으로 범위를 확대하기 위해 적극적으로 작업 중입니다.

<details><summary style="color:#5943b6; margin-top: 1em;"><a>취약성 해결 방법에 지원되는 CWE의 전체 목록 보기</a></summary>

<ul>
  <li>CWE-23: 상대 경로 트래버설</li>
  <li>CWE-73: 파일 이름 또는 경로의 외부 제어</li>
  <li>CWE-78: OS 명령에 사용되는 특수 요소의 부적절한 중립화('OS 명령 인젝션')</li>
  <li>CWE-80: 웹 페이지의 스크립트 관련 HTML 태그의 부적절한 중립화(기본 XSS)</li>
  <li>CWE-89: SQL 명령에 사용되는 특수 요소의 부적절한 중립화('SQL 인젝션')</li>
  <li>CWE-116: 출력의 부적절한 인코딩 또는 이스케이프</li>
  <li>CWE-118: 인덱싱 가능 리소스에 대한 잘못된 액세스('범위 오류')</li>
  <li>CWE-119: 메모리 버퍼 범위 내의 작업에 대한 부적절한 제한</li>
  <li>CWE-120: 입력 크기 확인 없이 버퍼 복사('클래식 버퍼 오버플로우')</li>
  <li>CWE-126: 버퍼 오버리드</li>
  <li>CWE-190: 정수 오버플로우 또는 래핑</li>
  <li>CWE-200: 권한이 없는 행위자에게 민감한 정보 노출</li>
  <li>CWE-208: 관찰 가능한 타이밍 불일치</li>
  <li>CWE-209: 민감한 정보를 포함하는 오류 메시지 생성</li>
  <li>CWE-272: 최소 권한 위반</li>
  <li>CWE-287: 부적절한 인증</li>
  <li>CWE-295: 부적절한 인증서 유효성 검사</li>
  <li>CWE-297: 호스트 불일치가 있는 인증서의 부적합한 유효성 검사</li>
  <li>CWE-305: 기본 약점에 의한 인증 우회</li>
  <li>CWE-310: 암호화 문제</li>
  <li>CWE-311: 민감한 데이터의 암호화 부재</li>
  <li>CWE-323: 암호화에서 Nonce, 키 쌍 재사용</li>
  <li>CWE-327: 손상되었거나 위험한 암호화 알고리즘 사용</li>
  <li>CWE-328: 약한 해시 사용</li>
  <li>CWE-330: 불충분하게 무작위인 값 사용</li>
  <li>CWE-338: 암호화적으로 약한 의사 난수 생성기(PRNG) 사용</li>
  <li>CWE-345: 데이터 진위성의 불충분한 유효성 검사</li>
  <li>CWE-346: 원본 유효성 검사 오류</li>
  <li>CWE-352: 사이트 간 요청 위조</li>
  <li>CWE-362: 공유 리소스를 사용한 동시 실행과 부적절한 동기화('경쟁 조건')</li>
  <li>CWE-369: 0으로 나누기</li>
  <li>CWE-377: 안전하지 않은 임시 파일</li>
  <li>CWE-378: 안전하지 않은 권한이 있는 임시 파일 만들기</li>
  <li>CWE-400: 제한되지 않은 리소스 소비</li>
  <li>CWE-489: 활성 디버그 코드</li>
  <li>CWE-521: 약한 비밀번호 요구 사항</li>
  <li>CWE-539: 민감한 정보가 포함된 영구 쿠키 사용</li>
  <li>CWE-599: OpenSSL 인증서의 누락된 유효성 검사</li>
  <li>CWE-611: XML 외부 엔티티 참조의 부적절한 제한</li>
  <li>CWE-676: 잠재적으로 위험한 함수 사용</li>
  <li>CWE-704: 잘못된 타입 변환 또는 캐스트</li>
  <li>CWE-754: 비정상적이거나 예외적인 조건에 대한 부적절한 확인</li>
  <li>CWE-770: 제한 또는 제한 없이 리소스 할당</li>
  <li>CWE-1004: 'HttpOnly' 플래그가 없는 민감한 쿠키</li>
  <li>CWE-1275: SameSite 특성이 부적절한 민감한 쿠키</li>
</ul>
</details>

## 취약성 해결 방법을 위해 타사 AI API와 공유되는 데이터 {#data-shared-with-third-party-ai-apis-for-vulnerability-resolution}

다음 데이터는 타사 AI API와 공유됩니다.

- 취약성 이름
- 취약성 설명
- 식별자(CWE, OWASP)
- 취약한 코드 줄을 포함하는 전체 파일
- 취약한 코드 줄(줄 번호)

## 워크플로우 {#workflows}

취약성 해결은 다음 워크플로우에서 사용할 수 있습니다:

- 취약성 보고서에서 기존 취약성을 해결합니다.
- 머지 리퀘스트의 맥락에서 취약성을 해결합니다.

### 취약성 보고서에서 취약성 해결 {#resolve-a-vulnerability-from-the-vulnerability-report}

{{< history >}}

- 취약성 보고서에서 취약성을 해결합니다:
  - GitLab 16.7에서 GitLab.com에 [실험적 기능](../../../policy/development_stages_support.md#experiment)으로 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/10779)되었습니다.
  - GitLab 17.3에서 베타로 변경되었습니다.
  - GitLab 17.6 이상에서 GitLab Duo 애드온을 요구하도록 변경되었습니다.
- 취약성 해결 활동 아이콘:
  - GitLab 17.5에서 [`vulnerability_report_vr_badge`](https://gitlab.com/gitlab-org/gitlab/-/issues/486549) 플래그로 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/15036)되었습니다. 기본적으로 비활성화되었습니다.
  - GitLab 17.6에서 [기본적으로 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/171718)되었습니다.
  - GitLab 18.0에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/503568)하게 되었습니다. `vulnerability_report_vr_badge` 기능 플래그가 제거되었습니다.

{{< /history >}}

사전 요구 사항:

- 프로젝트에 대한 Maintainer 또는 Owner 역할.
- 취약성은 지원되는 분석기에서 SAST 발견 사항이어야 합니다.
  - 모든 [GitLab 지원 분석기](../sast/analyzers.md).
  - 취약성 위치와 각 취약성에 대한 CWE 식별자를 보고하는 적절히 통합된 타사 SAST 스캐너.
- 취약성은 [지원되는 유형](#supported-vulnerabilities-for-vulnerability-resolution)이어야 합니다.

취약성 보고서에서 취약성을 해결하려면:

1. 왼쪽 사이드바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. **안전함** > **취약점 보고서**를 선택합니다.
1. 선택 사항. 기본 필터를 제거하려면 **지우기** ({{< icon name="clear" >}})를 선택합니다.
1. 취약성 목록 위의 필터 막대를 선택합니다.
1. 나타나는 드롭다운 목록에서 **활동**을 선택한 다음 **GitLab Duo(AI)** 범주에서 **취약성 해결 방법 제공**을 선택합니다.
1. 필터 필드 외부를 선택합니다. 취약성 심각도 합계 및 일치하는 취약성 목록이 업데이트됩니다.
1. 해결하려는 SAST 취약성을 선택합니다.
   - 취약성 해결 방법을 지원하는 취약성 옆에 파란색 아이콘이 표시됩니다.
1. 오른쪽 위 모서리에서 **AI로 해결**을 선택합니다. 해당 버튼이 표시되지 않으면 **AI 작업**을(를) 선택한 다음 **AI로 해결**을 선택하세요.
   > [!warning]
   > 이 프로젝트가 공개 프로젝트인 경우, MR을 생성하면 취약성과 제시된 해결 방법이 공개적으로 노출됩니다. MR을 비공개로 생성하려면 [비공개 포크 생성](../../project/merge_requests/confidential.md)을 수행한 후 이 프로세스를 반복합니다.
1. MR에 추가 커밋을 추가합니다. 이렇게 하면 새 파이프라인이 실행됩니다.
1. 파이프라인이 완료된 후 [파이프라인 보안 탭](../detect/security_scanning_results.md)에서 취약성이 더 이상 나타나지 않는지 확인합니다.
1. 취약성 보고서에서 [취약성을 수동으로 업데이트](../vulnerability_report/_index.md#change-status-of-vulnerabilities)합니다.

AI 수정 제안을 포함하는 병합 요청이 열립니다. 제안된 변경 사항을 검토한 다음 표준 워크플로우에 따라 병합 요청을 처리합니다.

### 머지 리퀘스트에서 취약성 해결 {#resolve-a-vulnerability-in-a-merge-request}

{{< history >}}

- GitLab 17.6에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/14862)되었습니다.
- GitLab 17.7에서 [기본적으로 사용으로 설정](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/175150)되었습니다.
- GitLab 17.11에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/185452)합니다. `resolve_vulnerability_in_mr` 기능 플래그가 제거되었습니다.

{{< /history >}}

머지 리퀘스트에서 GitLab Duo 취약성 해결을 사용하여 병합 전에 취약성을 해결할 수 있습니다. 취약성 해결은 취약성 발견을 해결하는 머지 리퀘스트 제안 댓글을 자동으로 생성합니다.

사전 요구 사항:

- 프로젝트에 대한 Maintainer 또는 Owner 역할.
- 취약성은 지원되는 분석기에서 SAST 발견 사항이어야 합니다.
  - 모든 [GitLab 지원 분석기](../sast/analyzers.md).
  - 취약성 위치와 각 취약성에 대한 CWE 식별자를 보고하는 적절히 통합된 타사 SAST 스캐너.
- 취약성은 [지원되는 유형](#supported-vulnerabilities-for-vulnerability-resolution)이어야 합니다.

취약성 발견을 해결하려면:

1. 왼쪽 사이드바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. **머지 리퀘스트**를 선택합니다.
1. 병합 요청을 선택합니다.
   - 취약성 해결에서 지원하는 취약성 발견은 tanuki AI 아이콘 ({{< icon name="tanuki-ai" >}})으로 표시됩니다.
1. 지원되는 발견 사항을 선택하여 보안 발견 사항 대화 상자를 엽니다.
1. 오른쪽 아래 모서리에서 **AI로 해결**을 선택합니다.

   AI 수정 제안을 포함하는 댓글이 병합 요청에서 열립니다.
1. 제안된 변경 사항을 검토한 다음 표준 워크플로우에 따라 병합 요청 제안을 적용합니다.

## 문제 해결 {#troubleshooting}

취약성 해결에서 제안하는 수정을 생성하는 못하는 경우가 있습니다. 일반적인 원인은 다음과 같습니다.

- 오탐 탐지:
  - 수정을 제안하기 전에 AI 모델은 취약성이 유효한지 평가합니다. 취약성이 실제 취약성이 아니거나 수정할 가치가 없다고 판단할 수 있습니다.
  - 취약성이 테스트 코드에서 발생하면 이런 일이 발생할 수 있습니다. 조직에서 테스트 코드에서 발생하는 취약성을 수정하도록 선택할 수 있지만 모델이 이것을 오탐으로 평가하는 경우가 있습니다.
  - 취약성이 오탐이거나 수정할 가치가 없다고 생각하면 [취약성을 무시](../vulnerabilities/_index.md#vulnerability-status-values)하고 [일치하는 이유 선택](../vulnerabilities/_index.md#vulnerability-dismissal-reasons)해야 합니다.
    - SAST 구성을 사용자 지정하거나 GitLab SAST 규칙의 문제를 보고하려면 [SAST 규칙](../sast/rules.md)을 참조하세요.
- 일시적 또는 예기치 않은 오류:
  - 오류 메시지에 `an unexpected error has occurred`, `the upstream AI provider request timed out`, `something went wrong` 또는 유사한 원인이 표시될 수 있습니다.
  - 이러한 오류는 AI 공급자 또는 GitLab Duo의 일시적인 문제로 인해 발생할 수 있습니다.
  - 새 요청이 성공할 수 있으므로 취약성을 다시 해결하도록 시도할 수 있습니다.
  - 계속해서 이러한 오류가 표시되면 GitLab에 문의하여 도움을 받으세요.
- `Resolution target could not be found in the merge request, unable to create suggestion` 오류:
  - 이 오류는 대상 브랜치가 전체 보안 검사 파이프라인을 실행하지 않았을 때 발생할 수 있습니다. [병합 요청 설명서](../detect/security_scanning_results.md)를 참조하세요.
