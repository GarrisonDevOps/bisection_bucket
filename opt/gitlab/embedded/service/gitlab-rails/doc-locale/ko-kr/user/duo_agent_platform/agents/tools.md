---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 에이전트 도구
---

사용자 지정 에이전트에서 사용할 수 있는 도구는 다음과 같습니다.

## Web UI 및 IDE에서 사용 가능한 도구 {#tools-available-in-the-web-ui-and-ide}

{{< history >}}

- Get Previous Session Context 도구가 GitLab 19.4에서 [Get Session Context로 이름을 변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254136)했습니다.

{{< /history >}}

| 이름 | 도구 | 설명 |
|------|------|-------------|
| 병합 요청 검토자 추가 | `add_merge_request_reviewers` | 기존 검토자를 제거하지 않고 병합 요청에 검토자를 추가합니다. |
| 새 작업 추가 | `add_new_task` | 작업을 추가합니다. |
| 병합 요청 컨텍스트 검토 빌드 | `build_review_merge_request_context` | 코드 검토를 위한 종합적인 병합 요청 컨텍스트를 빌드합니다. |
| CI 린터 | `ci_linter` | CI/CD YAML 구성을 CI/CD 구문 규칙과 비교하여 검증합니다. |
| 취약성 확인 | `confirm_vulnerability` | 프로젝트의 취약성 상태를 `CONFIRMED`로 변경합니다. |
| 브랜치 생성 | `create_branch` | 리포지토리에 브랜치를 생성합니다. |
| 커밋 생성 | `create_commit` | 리포지토리에 여러 파일 작업이 포함된 커밋을 생성합니다. |
| 에픽 생성 | `create_epic` | 그룹에서 에픽을 생성합니다. |
| 이슈 생성 | `create_issue` | 프로젝트에서 이슈를 생성합니다. |
| 이슈 참고사항 생성 | `create_issue_note` | 이슈에 참고사항을 추가합니다. |
| 병합 요청 생성 | `create_merge_request` | 프로젝트에서 병합 요청을 생성합니다. |
| 병합 요청 차이 참고사항 생성 | `create_merge_request_diff_note` | 병합 요청에 인라인 차이 참고사항을 추가합니다. 빠른 작업은 지원되지 않습니다. |
| 병합 요청 참고사항 생성 | `create_merge_request_note` | 병합 요청에 참고사항을 추가합니다. 빠른 작업은 지원되지 않습니다. |
| 플랜 생성 | `create_plan` | 작업 목록을 생성합니다. |
| 취약성 이슈 생성 | `create_vulnerability_issue` | 프로젝트의 보안 취약성에 연결된 이슈를 생성합니다. |
| 작업 항목 생성 | `create_work_item` | 그룹 또는 프로젝트에서 작업 항목을 생성합니다. 빠른 작업은 지원되지 않습니다. |
| 작업 항목 참고사항 생성 | `create_work_item_note` | 작업 항목에 참고사항을 추가합니다. 빠른 작업은 지원되지 않습니다. |
| 취약성 무시 | `dismiss_vulnerability` | 프로젝트의 보안 취약성을 무시합니다. |
| 텍스트에서 줄 추출 | `extract_lines_from_text` | 텍스트에서 특정 줄을 추출합니다. |
| 커밋 가져오기 | `get_commit` | 프로젝트에서 커밋을 가져옵니다. |
| 커밋 주석 가져오기 | `get_commit_comments` | 프로젝트에서 커밋의 주석을 가져옵니다. |
| 커밋 차이 가져오기 | `get_commit_diff` | 프로젝트에서 커밋의 차이를 가져옵니다. |
| 현재 사용자 가져오기 | `get_current_user` | 현재 사용자에 대한 다음 정보를 가져옵니다: 사용자 이름, 직책, 선호 언어. |
| 다운스트림 파이프라인 가져오기 | `get_downstream_pipelines` | 다운스트림 파이프라인의 URL을 가져옵니다. |
| 에픽 가져오기 | `get_epic` | 그룹에서 에픽을 가져옵니다. |
| 에픽 참고사항 가져오기 | `get_epic_note` | 에픽에서 참고사항을 가져옵니다. |
| 실패한 브릿지 작업 가져오기 | `get_failing_bridge_jobs` | 파이프라인의 실패한 브릿지 작업과 각 다운스트림 파이프라인의 URL을 가져옵니다. |
| 이슈 가져오기 | `get_issue` | 프로젝트에서 이슈를 가져옵니다. |
| 이슈 참고사항 가져오기 | `get_issue_note` | 이슈에서 참고사항을 가져옵니다. |
| 작업 로그 가져오기 | `get_job_logs` | 작업의 추적을 가져옵니다. |
| 병합 요청 가져오기 | `get_merge_request` | 병합 요청에 대한 세부 정보를 가져옵니다. |
| 파이프라인 오류 가져오기 | `get_pipeline_errors` | 병합 요청의 최신 파이프라인에서 실패한 작업의 로그를 가져옵니다. |
| 파이프라인 실패 작업 가져오기 | `get_pipeline_failing_jobs` | 파이프라인에서 실패한 작업의 ID를 가져옵니다. |
| 플랜 가져오기 | `get_plan` | 작업 목록을 가져옵니다. |
| 프로젝트 가져오기 | `get_project` | 프로젝트에 대한 세부 정보를 가져옵니다. |
| 리포지토리 파일 가져오기 | `get_repository_file` | 원격 리포지토리에서 파일 내용을 가져옵니다. |
| 리포지토리 파일 가져오기 | `get_repository_files` | 단일 호출로 리포지토리에서 여러 파일의 내용을 가져옵니다. |
| 보안 발견 세부 정보 가져오기 | `get_security_finding_details` | ID와 이를 식별한 파이프라인 스캔의 ID로 잠재적 취약성의 세부 정보를 가져옵니다. |
| 세션 컨텍스트 가져오기 | `get_session_context` | 실행 중이거나 완료된 세션에서 컨텍스트를 가져옵니다. |
| 취약성 세부 정보 가져오기 | `get_vulnerability_details` | ID로 지정된 취약성에 대한 다음 정보를 가져옵니다: 기본 취약성 정보, 위치 세부 정보, CVE 보강 데이터, 탐지 파이프라인 정보, 세부 취약성 보고서 데이터. |
| 위키 페이지 가져오기 | `get_wiki_page` | 프로젝트 또는 그룹에서 모든 주석이 포함된 위키 페이지를 가져옵니다. |
| 작업 항목 가져오기 | `get_work_item` | 그룹 또는 프로젝트에서 작업 항목을 가져옵니다. |
| 작업 항목 참고사항 가져오기 | `get_work_item_notes` | 작업 항목의 모든 참고사항을 가져옵니다. |
| 작업 항목 상태 가져오기 | `get_work_item_statuses` | 그룹 또는 프로젝트에서 사용 가능한 작업 항목 상태를 가져옵니다. |
| GitLab API 가져오기 | `gitlab_api_get` | REST API 엔드포인트에 대한 읽기 전용 GET 요청을 수행합니다. |
| GitLab Blob 검색 | `gitlab_blob_search` | 그룹, 프로젝트 또는 인스턴스에서 파일 내용을 검색합니다. 그룹 또는 인스턴스 전체를 검색하려면 [고급](../../../integration/advanced_search/elasticsearch.md#enable-code-search-with-advanced-search) 또는 [정확 코드](../../../integration/zoekt/_index.md#enable-exact-code-search) 검색을 활성화해야 합니다.  |
| GitLab 커밋 검색 | `gitlab_commit_search` | 프로젝트 또는 그룹에서 커밋을 검색합니다. |
| GitLab 문서 검색 | `gitlab_documentation_search` | GitLab 문서에서 정보를 검색합니다. |
| GitLab GraphQL | `gitlab_graphql` | GraphQL API에 대해 읽기 전용 GraphQL 쿼리를 실행합니다. |
| GitLab 그룹 프로젝트 검색 | `gitlab_group_project_search` | 그룹에서 프로젝트를 검색합니다. |
| GitLab 이슈 검색 | `gitlab_issue_search` | 프로젝트 또는 그룹에서 이슈를 검색합니다. |
| GitLab 병합 요청 검색 | `gitlab_merge_request_search` | 프로젝트 또는 그룹에서 병합 요청을 검색합니다. |
| GitLab 마일스톤 검색 | `gitlab_milestone_search` | 프로젝트 또는 그룹에서 마일스톤을 검색합니다. |
| GitLab 참고사항 검색 | `gitlab_note_search` | 프로젝트에서 참고사항을 검색합니다. |
| GitLab 사용자 검색 | `gitlab__user_search` | 프로젝트 또는 그룹에서 사용자를 검색합니다. |
| GitLab 위키 Blob 검색 | `gitlab_wiki_blob_search` | 프로젝트 또는 그룹의 위키 내용을 검색합니다. |
| 취약성을 이슈로 연결 | `link_vulnerability_to_issue` | 이슈를 프로젝트의 보안 취약성에 연결합니다. |
| 취약성을 병합 요청으로 연결 | `link_vulnerability_to_merge_request` | GraphQL을 사용하여 보안 취약성을 프로젝트의 병합 요청에 연결합니다. |
| 모든 병합 요청 참고사항 나열 | `list_all_merge_request_notes` | 병합 요청의 모든 참고사항을 나열합니다. |
| 커밋 나열 | `list_commits` | 프로젝트에서 커밋을 나열합니다. |
| 에픽 참고사항 나열 | `list_epic_notes` | 에픽의 모든 참고사항을 나열합니다. |
| 에픽 나열 | `list_epics` | 그룹 및 해당 하위 그룹의 모든 에픽을 나열합니다. |
| 그룹 감사 이벤트 나열 | `list_group_audit_events` | 그룹의 감사 이벤트를 나열합니다. 그룹 감사 이벤트에 액세스하려면 소유자 역할이 있어야 합니다. |
| 인스턴스 감사 이벤트 나열 | `list_instance_audit_events` | 인스턴스 수준 감사 이벤트를 나열합니다. 인스턴스 감사 이벤트를 보려면 관리자여야 합니다. |
| 이슈 참고사항 나열 | `list_issue_notes` | 이슈의 모든 참고사항을 나열합니다. |
| 이슈 나열 | `list_issues` | 프로젝트의 모든 이슈를 나열합니다. |
| 병합 요청 차이 나열 | `list_merge_request_diffs` | 병합 요청의 변경된 파일 차이를 나열합니다. |
| MR 토론 나열 | `list_mr_discussions` | 병합 요청의 토론 스레드를 나열합니다. |
| 프로젝트 감사 이벤트 나열 | `list_project_audit_events` | 프로젝트의 감사 이벤트를 나열합니다. 프로젝트 감사 이벤트에 액세스하려면 소유자 역할이 있어야 합니다. |
| 리포지토리 트리 나열 | `list_repository_tree` | 리포지토리의 파일 및 디렉터리를 나열합니다. |
| 보안 발견 나열 | `list_security_findings` | 특정 파이프라인 보안 스캔의 임시 보안 발견 사항을 나열합니다. |
| 취약성 나열 | `list_vulnerabilities` | 프로젝트의 보안 취약성을 나열합니다. |
| 작업 항목 나열 | `list_work_items` | 프로젝트 또는 그룹의 작업 항목을 나열합니다. |
| SAST FP 분석을 GitLab에 게시 | `post_sast_fp_analysis_to_gitlab` | SAST 거짓 양성 탐지 분석 결과를 게시합니다. |
| 작업 제거 | `remove_task` | 작업 목록에서 작업을 제거합니다. |
| 토론에 회신 | `reply_to_discussion` | 병합 요청의 토론 스레드에 회신합니다. |
| 탐지된 취약성으로 되돌리기 | `revert_to_detected_vulnerability` | 취약성의 상태를 `detected`로 되돌립니다. |
| GLQL 쿼리 실행 | `run_glql_query` | 작업 항목, 에픽 및 병합 요청에 대한 GLQL 쿼리를 실행합니다. |
| 테스트 실행 | `run_tests` | 모든 언어 또는 프레임워크에 대한 테스트 명령을 실행합니다. |
| 토론 해결됨으로 설정 | `set_discussion_resolved` | 병합 요청의 토론 스레드의 해결된 상태를 설정합니다. |
| 작업 상태 설정 | `set_task_status` | 작업의 상태를 설정합니다. |
| MR 검토 제출 | `submit_mr_review` | 인라인 차이 주석, 평결 및 선택적 요약 참고사항이 포함된 병합 요청 검토를 제출합니다. |
| 에픽 업데이트 | `update_epic` | 그룹의 에픽을 업데이트합니다. |
| 이슈 업데이트 | `update_issue` | 프로젝트의 이슈를 업데이트합니다. |
| 병합 요청 업데이트 | `update_merge_request` | 병합 요청을 업데이트합니다. 대상 브랜치를 변경하거나 제목을 편집하거나 MR을 닫을 수 있습니다. |
| 작업 설명 업데이트 | `update_task_description` | 작업의 설명을 업데이트합니다. |
| 취약성 심각도 업데이트 | `update_vulnerability_severity` | 프로젝트의 취약성 심각도 수준을 업데이트합니다. |
| 작업 항목 업데이트 | `update_work_item` | 그룹 또는 프로젝트의 기존 작업 항목을 업데이트합니다. 빠른 작업은 지원되지 않습니다. |

## IDE 전용 도구 {#tools-available-in-the-ide-only}

| 이름 | 도구 | 설명 |
|------|------|-------------|
| 내용이 있는 파일 생성 | `create_file_with_contents` | 파일을 생성하고 내용을 작성합니다. |
| 파일 편집 | `edit_file` | 기존 파일을 편집합니다. |
| 파일 찾기 | `find_files` | 프로젝트에서 파일을 재귀적으로 찾습니다. |
| Grep | `grep` | 파일에서 텍스트 패턴을 재귀적으로 검색합니다. 이 도구는 `.gitignore` 파일 규칙을 준수합니다. |
| 디렉터리 나열 | `list_dir` | 프로젝트의 루트를 기준으로 하는 디렉터리에서 파일을 나열합니다. |
| Mkdir | `mkdir` | 현재 작업 트리에 디렉터리를 생성합니다. |
| 조건이 충족되면 나에게 알림 | `notify_me_when` | 조건이 충족될 때 에이전트를 다시 시작하도록 예약합니다(예: 파이프라인이 완료될 때). |
| 파일 읽기 | `read_file` | 파일의 내용을 읽습니다. |
| 파일 읽기 | `read_files` | 파일의 내용을 읽습니다. |
| 명령 실행 | `run_command` | 현재 작업 디렉터리에서 Bash 명령(Git 명령 포함)을 실행합니다. |
| Git 명령 실행 | `run_git_command` (더 이상 사용되지 않음) | 현재 작업 디렉터리에서 Git 명령을 실행합니다. 대신 `run_command`을 사용합니다. |
