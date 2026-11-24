---
stage: Security Risk Management
group: Security Policies
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: '자습서: 머지 리퀘스트 승인 정책 설정'
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

이 자습서에서는 [머지 리퀘스트 승인 정책](../../user/application_security/policies/merge_request_approval_policies.md)을 생성하고 구성하는 방법을 보여줍니다. 이러한 정책은 스캔 결과에 따라 작업을 수행하도록 설정할 수 있습니다. 예를 들어 이 자습서에서는 머지 리퀘스트에서 취약성이 감지되면 지정된 두 사용자의 승인을 요구하는 정책을 설정합니다.

머지 리퀘스트 승인 정책을 설정하려면:

1. [테스트 프로젝트 생성](#create-a-test-project).
1. [머지 리퀘스트 승인 정책 추가](#add-a-merge-request-approval-policy).
1. [머지 리퀘스트 승인 정책 테스트](#test-the-merge-request-approval-policy).

## 시작하기 전에 {#before-you-begin}

- 이 자습서에 사용하는 네임스페이스에는 자신을 포함하여 최소 3명의 사용자가 있어야 합니다. 다른 사용자 2명이 없으면 먼저 생성해야 합니다. 자세한 내용은 [사용자 생성](../../user/profile/account/create_accounts.md)을 참조하세요.
- 기존 그룹에서 새 프로젝트를 만들 수 있는 권한이 필요합니다.

## 테스트 프로젝트 생성 {#create-a-test-project}

1. 오른쪽 위 모서리에서 **새로 만들기**({{< icon name="plus" >}}) 및 **새 프로젝트/리포지토리**를 선택합니다.
1. **빈 프로젝트 생성**을 선택합니다.
1. 필드를 완성합니다.
   - **프로젝트 이름**: `sast-scan-result-policy`.
   - **정적 애플리케이션 보안 테스트(SAST) 활성화** 확인란을 선택합니다.
1. **프로젝트 생성**을 선택합니다.
1. 기본 브랜치를 보호하려면:
   1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 `sast-scan-result-policy`를 입력합니다.
   1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
   1. **브랜치 규칙**을 확장합니다.
   1. **브랜치 규칙 추가** > **브랜치 이름 또는 패턴**을 선택합니다.
   1. 드롭다운 목록에서 `main` (또는 기본 브랜치)을 검색하여 선택한 후 **브랜치 규칙 생성**을 선택합니다.
   1. **머지 허용** 섹션에서 **편집**을 선택하고 **유지관리자**로 설정한 후 **변경사항 저장**을 선택합니다.
   1. **푸시와 머지가 허용됨** 섹션에서 **편집**을 선택하고 **아무도 없음**으로 설정한 후 **변경사항 저장**을 선택합니다.

## 머지 리퀘스트 승인 정책 추가 {#add-a-merge-request-approval-policy}

이제 테스트 프로젝트에 머지 리퀘스트 승인 정책을 추가합니다:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 `sast-scan-result-policy` 프로젝트를 찾습니다.
1. **안전함** > **정책**을 선택합니다.
1. **새 정책**을 선택합니다.
1. **머지 리퀘스트 승인 정책**에서 **정책 선택**을 선택합니다.
1. 필드를 완성합니다.
   - **이름**: `sast-scan-result-policy`
   - **정책 상태**: **Enabled (활성화됨)**
1. **새 규칙 추가**를 선택하고 규칙을 구성합니다:
   - 스캔 유형에 대해 **보안 스캔**을 **SAST**와 함께 선택합니다.
   - 대상으로 **모든 보호된 브랜치**를 **예외 없음**과 함께 선택합니다.
   - 취약성 개수에 대해 **다음 보다 큼**을 선택하고 `0`을 입력합니다.
1. **전역 설정**에서 심각도 및 상태를 구성합니다:
   - **심각도:**: **모든 심각도 수준**
   - **상태**: **신규** + **모든 취약성 상태**

1. **조치**을 다음과 같이 설정합니다:

   ```plaintext
   THEN Require approval from | 2 | of the following approvers:
   ```

1. 2명의 사용자를 선택합니다.
1. **머지 리퀘스트로 설정**을 선택합니다.

   애플리케이션은 정책을 저장할 새 프로젝트를 생성하고 정책을 정의하는 머지 리퀘스트를 생성합니다.
1. **머지**를 선택합니다.
1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 `sast-scan-result-policy` 프로젝트를 찾습니다.
1. **안전함** > **정책**을 선택합니다.

   이전 단계에서 추가한 정책 목록을 확인할 수 있습니다.

## 머지 리퀘스트 승인 정책 테스트 {#test-the-merge-request-approval-policy}

잘했습니다. 머지 리퀘스트 승인 정책을 생성했습니다. 이를 테스트하려면 일부 취약성을 생성하고 결과를 확인합니다:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 `sast-scan-result-policy` 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **리포지토리**를 선택합니다.
1. **추가** ({{< icon name="plus" >}}) 드롭다운 목록에서 **새 파일**을 선택합니다.
1. **파일명** 필드에 `main.ts`을 입력합니다.
1. 파일의 내용에 다음을 복사합니다:

   ```typescript
   // Non-literal require - tsr-detect-non-literal-require
   var lib: String = 'fs'
   require(lib)

   // Eval with variable - tsr-detect-eval-with-expression
   var myeval: String = 'console.log("Hello.");';
   eval(myeval);

   // Unsafe Regexp - tsr-detect-unsafe-regexp
   const regex: RegExp = /(x+x+)+y/;

   // Non-literal Regexp - tsr-detect-non-literal-regexp
   var myregexpText: String = "/(x+x+)+y/";
   var myregexp: RegExp = new RegExp(myregexpText);
   myregexp.test("(x+x+)+y");

   // Markup escaping disabled - tsr-detect-disable-mustache-escape
   var template: Object = new Object;
   template.escapeMarkup = false;

   // Detects HTML injections - tsr-detect-html-injection
   var element: Element =  document.getElementById("mydiv");
   var content: String = "mycontent"
   Element.innerHTML = content;

   // Timing attack - tsr-detect-possible-timing-attacks
   var userInput: String = "Jane";
   var auth: String = "Jane";
   if (userInput == auth) {
     console.log(userInput);
   }
   ```

1. **커밋 메시지** 필드에 `Add vulnerable file`을 입력합니다.
1. **대상 브랜치** 필드에 `test-branch`을 입력합니다.
1. **변경 사항 커밋**을 선택합니다. **새 머지 리퀘스트** 양식이 열립니다.
1. **머지 리퀘스트 생성**을 선택합니다.
1. 새 머지 리퀘스트에서 `Create merge request`을 선택합니다.

   파이프라인이 완료될 때까지 기다립니다. 몇 분이 걸릴 수 있습니다.

머지 리퀘스트 **리포트** 탭에서 보안 스캔이 잠재적 취약성 1개를 감지했음을 확인합니다. 머지 리퀘스트 승인 정책에서 정의한 대로 머지 리퀘스트가 차단되고 승인을 기다리는 중입니다.

이제 머지 리퀘스트 승인 정책을 설정하고 사용하여 취약성을 포착하는 방법을 알게 되었습니다!
