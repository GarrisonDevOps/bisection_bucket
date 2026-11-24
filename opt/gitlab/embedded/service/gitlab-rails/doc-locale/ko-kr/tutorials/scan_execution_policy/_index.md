---
stage: Security Risk Management
group: Security Policies
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: '자습서: 스캔 실행 정책 설정'
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

이 자습서는 [검사 실행 정책](../../user/application_security/policies/scan_execution_policies.md)을 만들고 적용하는 방법을 보여줍니다. 이러한 정책은 CI/CD 파이프라인의 일부로 애플리케이션 보안 도구를 시행합니다. 이 자습서에서는 두 프로젝트의 CI/CD 파이프라인에서 시크릿 검색을 시행하는 정책을 만듭니다.

이 튜토리얼에서 수행하는 작업은 다음과 같습니다:

- [프로젝트 A 만들기](#create-project-a)
- [스캔 실행 정책 만들기](#create-the-scan-execution-policy)
- [프로젝트 A를 사용하여 스캔 실행 정책 테스트](#test-the-scan-execution-policy-with-project-a)
- [프로젝트 B 만들기](#create-project-b)
- [프로젝트 B를 보안 정책 프로젝트에 연결](#link-project-b-to-the-security-policy-project)
- [프로젝트 B를 사용하여 스캔 실행 정책 테스트](#test-the-scan-execution-policy-with-project-b)

## 시작하기 전에 {#before-you-begin}

- 기존 그룹에서 새 프로젝트를 만들 수 있는 권한이 필요합니다.

## 프로젝트 A 만들기 {#create-project-a}

표준 워크플로우에서는 이미 기존 프로젝트가 있을 수 있습니다. 이 자습서에서는 처음부터 시작하므로 첫 번째 단계는 프로젝트를 만드는 것입니다.

프로젝트 A를 만들려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **새 프로젝트**를 선택합니다.
1. **빈 프로젝트 생성**을 선택합니다.
1. 필드를 완성합니다. **프로젝트 이름**의 경우 `go-example-a`을 입력합니다.
1. **프로젝트 생성**을 선택합니다.
1. **추가** ({{< icon name="plus" >}}) > **새 파일**을 선택합니다.
1. 파일 이름에 `helloworld.go`을 입력합니다.
1. 다음 Go 코드 예제를 파일에 복사하여 붙여넣습니다.

   ```go
   package main
   import "fmt"
   func main() {
       fmt.Println("Hello world")
   }
   ```

1. **변경 사항 커밋**을 선택합니다.

다음 단계는 스캔 실행 정책을 만드는 것입니다. 첫 번째 보안 정책을 만들면 정책 프로젝트가 만들어집니다. 정책 프로젝트는 이와 연결된 프로젝트에서 만든 보안 정책을 저장합니다. 정책을 보호하는 프로젝트와 분리하면 보안 구성을 재사용할 수 있고 유지 관리하기가 더 쉬워집니다.

## 스캔 실행 정책 만들기 {#create-the-scan-execution-policy}

스캔 실행 정책을 만들려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 `go-example-a` 프로젝트를 검색합니다.
1. **안전함** > **정책**으로 이동합니다.
1. **새 정책**을 선택합니다.
1. **실행 정책 스캔** 섹션에서 **정책 선택**을 선택합니다.
1. 필드를 완성합니다.
   - **이름**: 시크릿 검색을 시행합니다.
   - **정책 상태**: 활성화됨.
   - **조치**: 시크릿 검색 스캔을 실행합니다.
   - **조건**: 모든 브랜치에 대해 파이프라인이 실행될 때마다 트리거됩니다.
1. **머지 리퀘스트로 설정**을 선택합니다.

   정책 프로젝트 `go-example-a - Security project`가 만들어지고 머지 리퀘스트가 만들어집니다.
1. 선택사항. 머지 리퀘스트의 **변경사항** 탭에서 생성된 정책 YAML을 검토합니다.
1. **개요** 탭으로 이동하여 **머지**를 선택합니다.
1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 `go-example-a` 프로젝트를 검색합니다.
1. **안전함** > **정책**으로 이동합니다.

이제 모든 브랜치의 모든 MR에 대해 시크릿 검색 스캔을 실행하는 스캔 실행 정책이 있습니다. 프로젝트 A에서 머지 리퀘스트를 만들어 정책을 테스트합니다.

## 프로젝트 A를 사용하여 스캔 실행 정책 테스트 {#test-the-scan-execution-policy-with-project-a}

스캔 실행 정책을 테스트하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 `go-example-a` 프로젝트를 찾습니다.
1. **코드** > **리포지토리**로 이동합니다.
1. `helloworld.go` 파일을 선택합니다.
1. **편집** > **단일 파일 편집**을 선택합니다.
1. `fmt.Println("hello world")` 줄 바로 다음에 다음 줄을 추가합니다:

   ```plaintext
   var GitLabFeedToken = "feed_token=eFLISqaBym4EjAefkl58"
   ```

1. **대상 브랜치** 필드에 `feature-a`을 입력합니다.
1. **변경 사항 커밋**을 선택합니다.
1. 머지 리퀘스트 페이지가 열리면 **머지 리퀘스트 생성**를 선택합니다.

   스캔 실행 정책이 작동했는지 확인해 봅시다. 시크릿 검색이 모든 브랜치에 대해 파이프라인이 실행될 때마다 실행되도록 지정했다는 점을 기억하세요.
1. 방금 만든 머지 리퀘스트에서 **파이프라인** 탭으로 이동하여 만든 파이프라인을 선택합니다.

   여기서 시크릿 검색 작업이 실행되었음을 확인할 수 있습니다. 테스트 시크릿을 감지했는지 확인해 봅시다.
1. 시크릿 검색 작업을 선택합니다.

   작업 로그의 하단 근처에 다음 출력이 예제 시크릿이 감지되었음을 확인합니다.

   ```plaintext
   [INFO] [secrets] [2023-09-04T03:46:36Z] ▶ 3:46AM INF 1 commits scanned.
   [INFO] [secrets] [2023-09-04T03:46:36Z] ▶ 3:46AM INF scan completed in 60ms
   [INFO] [secrets] [2023-09-04T03:46:36Z] ▶ 3:46AM WRN leaks found: 1
   ```

한 프로젝트의 정책이 작동하는 것을 확인했습니다. 다른 프로젝트를 만들고 동일한 정책을 적용합니다.

## 프로젝트 B 만들기 {#create-project-b}

프로젝트 B를 만들려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **새 프로젝트**를 선택합니다.
1. **빈 프로젝트 생성**을 선택합니다.
1. 필드를 완성합니다. **프로젝트 이름**의 경우 `go-example-b`을 입력합니다.
1. **프로젝트 생성**을 선택합니다.
1. **추가** ({{< icon name="plus" >}}) > **새 파일**을 선택합니다.
1. 파일 이름에 `helloworld.go`을 입력합니다.
1. 다음 Go 코드 예제를 파일에 복사하여 붙여넣습니다.

   ```go
   package main
   import "fmt"
   func main() {
       fmt.Println("Hello world")
   }
   ```

1. **변경 사항 커밋**을 선택합니다.

이제 다른 프로젝트가 있으므로 동일한 정책 프로젝트에 연결합니다.

## 프로젝트 B를 보안 정책 프로젝트에 연결 {#link-project-b-to-the-security-policy-project}

프로젝트 B를 보안 정책 프로젝트에 연결하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 `go-example-b` 프로젝트를 찾습니다.
1. **안전함** > **정책**으로 이동합니다.
1. **정책 프로젝트 편집**을 선택합니다.
1. 드롭다운 목록을 선택한 다음 이 자습서의 시작 부분에서 만든 보안 정책 프로젝트를 검색합니다.
1. **저장**을 선택합니다.

프로젝트 B를 동일한 정책 프로젝트에 연결하면 동일한 정책이 적용됩니다. 스캔 실행 정책은 모든 브랜치의 모든 MR에 대해 시크릿 검색 스캔을 실행합니다. 프로젝트 B에서 MR을 만들어 정책을 테스트해 봅시다.

## 프로젝트 B를 사용하여 스캔 실행 정책 테스트 {#test-the-scan-execution-policy-with-project-b}

스캔 실행 정책을 테스트하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 `go-example-b` 프로젝트를 찾습니다.
1. **코드** > **리포지토리**로 이동합니다.
1. `helloworld.go` 파일을 선택합니다.
1. **편집** > **단일 파일 편집**을 선택합니다.
1. `fmt.Println("hello world")` 줄 바로 다음에 다음 줄을 추가합니다:

   ```plaintext
   var AdobeClient = "4ab4b080d9ce4072a6be2629c399d653"
   ```

1. **대상 브랜치** 필드에 `feature-b`을 입력합니다.
1. **변경 사항 커밋**을 선택합니다.
1. 머지 리퀘스트 페이지가 열리면 **머지 리퀘스트 생성**를 선택합니다.

   스캔 실행 정책이 작동했는지 확인해 봅시다. 시크릿 검색이 모든 브랜치에 대해 파이프라인이 실행될 때마다 실행되도록 지정했다는 점을 기억하세요.
1. 방금 만든 머지 리퀘스트에서 **파이프라인** 탭으로 이동하여 만든 파이프라인을 선택합니다.
1. 방금 만든 머지 리퀘스트에서 파이프라인의 ID를 선택합니다.

   여기서 시크릿 검색 작업이 실행되었음을 확인할 수 있습니다. 테스트 시크릿을 감지했는지 확인해 봅시다.
1. 시크릿 검색 작업을 선택합니다.

   작업 로그의 하단 근처에 다음 출력이 예제 시크릿이 감지되었음을 확인합니다.

   ```plaintext
   [INFO] [secrets] [2023-09-04T04:22:28Z] ▶ 4:22AM INF 1 commits scanned.
   [INFO] [secrets] [2023-09-04T04:22:28Z] ▶ 4:22AM INF scan completed in 58.2ms
   [INFO] [secrets] [2023-09-04T04:22:28Z] ▶ 4:22AM WRN leaks found: 1
   ```

축하합니다. 스캔 실행 정책을 만들고 프로젝트에 시행하는 방법을 배웠습니다.
