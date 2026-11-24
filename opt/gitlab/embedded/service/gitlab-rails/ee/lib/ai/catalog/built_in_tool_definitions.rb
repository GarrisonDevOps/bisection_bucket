# frozen_string_literal: true

module Ai
  module Catalog
    module BuiltInToolDefinitions
      extend ActiveSupport::Concern

      # Tools removed from the catalog. Their IDs and names must never be
      # reused, because persisted agent tool lists may still reference them.
      RETIRED_TOOLS = {
        87 => "post_duo_code_review" # https://gitlab.com/gitlab-org/gitlab/-/work_items/604613
      }.freeze

      ITEMS = [
        {
          id: 1,
          name: "gitlab_blob_search",
          title: "Gitlab Blob Search",
          description: "Search for blobs in the specified GitLab group or project. In GitLab, a \"blob\" " \
            "refers to a file's content in a specific version of the repository."
        },
        {
          id: 2,
          name: "ci_linter",
          title: "CI Linter",
          description: "Validate a project's CI/CD YAML configuration."
        },
        {
          id: 3,
          name: "run_git_command",
          title: "Run Git Command",
          description: "Runs a git command in the repository working directory."
        },
        {
          id: 4,
          name: "gitlab_commit_search",
          title: "Gitlab Commit Search",
          description: "Search for commits in the specified GitLab project or group."
        },
        {
          id: 5,
          name: "create_epic",
          title: "Create Epic",
          description: "Create a new epic in a GitLab group."
        },
        {
          id: 6,
          name: "create_issue",
          title: "Create Issue",
          description: "Create a new issue in a GitLab project."
        },
        {
          id: 7,
          name: "create_issue_note",
          title: "Create Issue Note",
          description: "Create a new note (comment) on a GitLab issue."
        },
        {
          id: 8,
          name: "create_merge_request",
          title: "Create Merge Request",
          description: "Create a new merge request in the specified project."
        },
        {
          id: 9,
          name: "create_merge_request_note",
          title: "Create Merge Request Note",
          description: "Add a comment to a merge request."
        },
        {
          id: 10,
          name: "edit_file",
          title: "Edit File",
          description: "Edit an existing file."
        },
        {
          id: 11,
          name: "find_files",
          title: "Find Files",
          description: "Find files, recursively, with names matching a specific pattern in the repository."
        },
        {
          id: 12,
          name: "get_commit",
          title: "Get Commit",
          description: "Get a single commit from a GitLab project repository, and optionally " \
            "its diff or notes."
        },
        {
          id: 13,
          name: "get_commit_comments",
          title: "Get Commit Comments",
          description: "Get the comments on a specific commit in a GitLab project."
        },
        {
          id: 14,
          name: "get_commit_diff",
          title: "Get Commit Diff",
          description: "Get the diff of a specific commit in a GitLab project."
        },
        {
          id: 15,
          name: "get_epic",
          title: "Get Epic",
          description: "Get a single epic in a GitLab group"
        },
        {
          id: 16,
          name: "get_epic_note",
          title: "Get Epic Note",
          description: "Get a single note (comment) from a specific epic."
        },
        {
          id: 17,
          name: "get_issue",
          title: "Get Issue",
          description: "Get a single issue in a GitLab project."
        },
        {
          id: 18,
          name: "get_issue_note",
          title: "Get Issue Note",
          description: "Get a single note (comment) from a specific issue."
        },
        {
          id: 19,
          name: "get_job_logs",
          title: "Get Job Logs",
          description: "Get the trace for a job."
        },
        {
          id: 20,
          name: "get_merge_request",
          title: "Get Merge Request",
          description: "Fetch details about the merge request, and optionally its diffs, commits, " \
            "notes, pipelines, or discussions."
        },
        {
          id: 21,
          name: "get_pipeline_errors",
          title: "Get Pipeline Errors",
          description: "Get the logs for failed jobs in the latest pipeline in a merge request."
        },
        {
          id: 22,
          name: "get_project",
          title: "Get Project",
          description: "Fetch details about the project"
        },
        {
          id: 23,
          name: "get_repository_file",
          title: "Get Repository File",
          description: "Get the contents of a file from a remote repository."
        },
        {
          id: 24,
          name: "grep",
          title: "Grep",
          description: "Search for text patterns in files. This tool uses searches, recursively, through " \
            "all files in the given directory, respecting .gitignore rules."
        },
        {
          id: 25,
          name: "gitlab_group_project_search",
          title: "Gitlab Group Project Search",
          description: "Search for projects within a specified GitLab group."
        },
        {
          id: 26,
          name: "gitlab_issue_search",
          title: "Gitlab Issue Search",
          description: "Search for issues in the specified GitLab project or group."
        },
        {
          id: 27,
          name: "list_all_merge_request_notes",
          title: "List All Merge Request Notes",
          description: "List all notes (comments) on a merge request."
        },
        {
          id: 28,
          name: "list_commits",
          title: "List Commits",
          description: "List commits in a GitLab project repository."
        },
        {
          id: 29,
          name: "list_dir",
          title: "List Dir",
          description: "Lists files in the given directory relative to the root of the project."
        },
        {
          id: 30,
          name: "list_epic_notes",
          title: "List Epic Notes",
          description: "Get a list of all notes (comments) for a specific epic."
        },
        {
          id: 31,
          name: "list_epics",
          title: "List Epics",
          description: "Get all epics of the requested group and its subgroups."
        },
        {
          id: 32,
          name: "list_issue_notes",
          title: "List Issue Notes",
          description: "Get a list of all notes (comments) for a specific issue."
        },
        {
          id: 33,
          name: "list_issues",
          title: "List Issues",
          description: "List issues in a GitLab project."
        },
        {
          id: 34,
          name: "list_merge_request_diffs",
          title: "List Merge Request Diffs",
          description: "Fetch the diffs of the files changed in a merge request."
        },
        {
          id: 35,
          name: "gitlab_merge_request_search",
          title: "Gitlab Merge Request Search",
          description: "Search for merge requests in the specified GitLab project or group."
        },
        {
          id: 36,
          name: "gitlab_milestone_search",
          title: "Gitlab Milestone Search",
          description: "Search for milestones in the specified GitLab project or group."
        },
        {
          id: 37,
          name: "mkdir",
          title: "Mkdir",
          description: "Create a new directory using the mkdir command. The directory creation is " \
            "restricted to the current working directory tree."
        },
        {
          id: 38,
          name: "gitlab_note_search",
          title: "Gitlab Note Search",
          description: "Search for notes in the specified GitLab project."
        },
        {
          id: 39,
          name: "read_file",
          title: "Read File",
          description: "Read the contents of a file."
        },
        {
          id: 40,
          name: "run_command",
          title: "Run Command",
          description: "Run a shell command in the working directory. Git commands are not supported."
        },
        {
          id: 41,
          name: "set_task_status",
          title: "Set Task Status",
          description: "Set the status of a task in a workflow plan."
        },
        {
          id: 42,
          name: "update_epic",
          title: "Update Epic",
          description: "Update an existing epic in a GitLab group."
        },
        {
          id: 43,
          name: "update_issue",
          title: "Update Issue",
          description: "Update an existing issue in a GitLab project."
        },
        {
          id: 44,
          name: "update_merge_request",
          title: "Update Merge Request",
          description: "Updates an existing merge request. You can change the target branch, title, or " \
            "even close the MR."
        },
        {
          id: 45,
          name: "gitlab__user_search",
          title: "Gitlab User Search",
          description: "Search for users in the specified GitLab project or group."
        },
        {
          id: 46,
          name: "gitlab_wiki_blob_search",
          title: "Gitlab Wiki Blob Search",
          description: "Search for wiki blobs in the specified GitLab project or group. In GitLab, a " \
            "\"blob\" refers to a file's content in a specific version of the repository."
        },
        {
          id: 47,
          name: "create_file_with_contents",
          title: "Create File With Contents",
          description: "Create a file with the provided contents."
        },
        {
          id: 48,
          name: "gitlab_documentation_search",
          title: "Gitlab Documentation Search",
          description: "Search GitLab documentation."
        },
        {
          id: 49,
          name: "get_current_user",
          title: "Get Current User",
          description: "View the current user's username, job title, and preferred languages."
        },
        {
          id: 50,
          name: "add_new_task",
          title: "Add New Task",
          description: "Add a task to a workflow plan."
        },
        {
          id: 51,
          name: "create_vulnerability_issue",
          title: "Create Vulnerability Issue",
          description: "Create a GitLab issue linked to one or more vulnerabilities."
        },
        {
          id: 52,
          name: "read_files",
          title: "Read Files",
          description: "Read one or more files in a single operation."
        },
        {
          id: 53,
          name: "get_work_item",
          title: "Get Work Item",
          description: "Get a work item from a GitLab group or project."
        },
        {
          id: 54,
          name: "create_plan",
          title: "Create Plan",
          description: "Create a task plan for a workflow."
        },
        {
          id: 55,
          name: "get_plan",
          title: "Get Plan",
          description: "Fetch a list of tasks for a workflow.    " \
            "A plan consists of a list of tasks and the status of each task."
        },
        {
          id: 56,
          name: "update_task_description",
          title: "Update Task Description",
          description: "Update a task description in a workflow plan."
        },
        {
          id: 57,
          name: "revert_to_detected_vulnerability",
          title: "Revert To Detected Vulnerability",
          description: "Return a vulnerability to the 'detected' status."
        },
        {
          id: 58,
          name: "get_session_context",
          title: "Get Session Context",
          description: "Retrieve context from a previous or running session."
        },
        {
          id: 59,
          name: "list_repository_tree",
          title: "List Repository Tree",
          description: "Browse files and directories in a GitLab repository."
        },
        {
          id: 60,
          name: "create_work_item_note",
          title: "Create Work Item Note",
          description: "Add a comment to a work item."
        },
        {
          id: 61,
          name: "remove_task",
          title: "Remove Task",
          description: "Remove a task from a workflow plan."
        },
        {
          id: 62,
          name: "update_vulnerability_severity",
          title: "Update Vulnerability Severity",
          description: "Change the severity of one or more vulnerabilities."
        },
        {
          id: 63,
          name: "list_project_audit_events",
          title: "List Project Audit Events",
          description: "List audit events for a GitLab project."
        },
        {
          id: 64,
          name: "list_group_audit_events",
          title: "List Group Audit Events",
          description: "List audit events for a GitLab group."
        },
        {
          id: 65,
          name: "link_vulnerability_to_issue",
          title: "Link Vulnerability To Issue",
          description: "Link a GitLab issue to one or more vulnerabilities."
        },
        {
          id: 66,
          name: "list_instance_audit_events",
          title: "List Instance Audit Events",
          description: "List instance-level audit events."
        },
        {
          id: 67,
          name: "get_vulnerability_details",
          title: "Get Vulnerability Details",
          description: "Get details about a GitLab vulnerability."
        },
        {
          id: 68,
          name: "dismiss_vulnerability",
          title: "Dismiss Vulnerability",
          description: "Dismiss a security vulnerability in a GitLab project."
        },
        {
          id: 69,
          name: "confirm_vulnerability",
          title: "Confirm Vulnerability",
          description: "Confirm a security vulnerability in a GitLab project."
        },
        {
          id: 70,
          name: "update_work_item",
          title: "Update Work Item",
          description: "Update a work item in a GitLab group or project."
        },
        {
          id: 71,
          name: "list_work_items",
          title: "List Work Items",
          description: "List work items in a GitLab project or group."
        },
        {
          id: 72,
          name: "create_commit",
          title: "Create Commit",
          description: "Create a commit from file changes in a GitLab repository."
        },
        {
          id: 73,
          name: "list_vulnerabilities",
          title: "List Vulnerabilities",
          description: "List vulnerabilities in a GitLab project."
        },
        {
          id: 74,
          name: "get_work_item_notes",
          title: "Get Work Item Notes",
          description: "List comments on a GitLab work item."
        },
        {
          id: 75,
          name: "create_work_item",
          title: "Create Work Item",
          description: "Create a work item in a GitLab group or project."
        },
        {
          id: 76,
          name: "get_wiki_page",
          title: "Get Wiki Page",
          description: "Get a wiki page and its comments from a GitLab project or group."
        },
        {
          id: 77,
          name: "get_security_finding_details",
          title: "Get Security Finding Details",
          description: "Get details about a security finding from a pipeline scan."
        },
        {
          id: 78,
          name: "gitlab_api_get",
          title: "Gitlab Api Get",
          description: "Make read-only requests to GitLab's REST API."
        },
        {
          id: 79,
          name: "gitlab_graphql",
          title: "Gitlab Graphql",
          description: "Run read-only GraphQL queries against the GitLab API."
        },
        {
          id: 80,
          name: "link_vulnerability_to_merge_request",
          title: "Link Vulnerability To Merge Request",
          description: "Link a security vulnerability to a merge request."
        },
        {
          id: 81,
          name: "get_pipeline_failing_jobs",
          title: "Get Pipeline Failing Jobs",
          description: "Get failed jobs from a pipeline."
        },
        {
          id: 82,
          name: "run_tests",
          title: "Run Tests",
          description: "Run tests in a project."
        },
        {
          id: 83,
          name: "extract_lines_from_text",
          title: "Extract Lines From Text",
          description: "Extract selected lines from text."
        },
        {
          id: 84,
          name: "list_security_findings",
          title: "List Security Findings",
          description: "List security findings from a GitLab pipeline scan."
        },
        {
          id: 85,
          name: "build_review_merge_request_context",
          title: "Build Review Merge Request Context",
          description: "Build merge request context for code review."
        },
        {
          id: 86,
          name: "post_sast_fp_analysis_to_gitlab",
          title: "Post Sast Fp Analysis To Gitlab",
          description: "Post false-positive analysis for a SAST vulnerability."
        },
        # id 87 is retired, see RETIRED_TOOLS
        {
          id: 88,
          name: "run_glql_query",
          title: "Run GLQL Query",
          description: "Search GitLab work items, epics, and merge requests with a GLQL query."
        },
        {
          id: 89,
          name: "get_merge_request_conflicts",
          title: "Get Merge Request Conflicts",
          description: "Get merge conflict details for a merge request."
        },
        {
          id: 90,
          name: "get_glql_schema",
          title: "Get GLQL Schema",
          description: "Deprecated GLQL schema lookup; use the current instance schema instead."
        },
        {
          id: 91,
          name: "get_work_item_statuses",
          title: "Get Work Item Statuses",
          description: "Get the work item statuses available in a GitLab group or project."
        },
        {
          id: 92,
          name: "create_merge_request_diff_note",
          title: "Create Merge Request Diff Note",
          description: "Add an inline comment to a merge request diff."
        },
        {
          id: 93,
          name: "start_flow",
          title: "Start Flow",
          description: "Start an asynchronous task with a specialist GitLab agent."
        },
        {
          id: 94,
          name: "add_merge_request_reviewers",
          title: "Add Merge Request Reviewers",
          description: "Add reviewers to a merge request, keeping the reviewers that are already assigned."
        },
        {
          id: 95,
          name: "create_branch",
          title: "Create Branch",
          description: "Create a new branch in a GitLab repository."
        },
        {
          id: 96,
          name: "get_downstream_pipelines",
          title: "Get Downstream Pipelines",
          description: "Get the URLs for downstream pipelines of a pipeline."
        },
        {
          id: 97,
          name: "get_failing_bridge_jobs",
          title: "Get Failing Bridge Jobs",
          description: "Get the failed bridge jobs in a pipeline, with the URL of each failed bridge's " \
            "downstream pipeline."
        },
        {
          id: 98,
          name: "get_repository_files",
          title: "Get Repository Files",
          description: "Get the contents of multiple files from a remote GitLab repository in a single call. " \
            "Accepts a mix of explicit file paths and glob patterns."
        },
        {
          id: 99,
          name: "list_mr_discussions",
          title: "List MR Discussions",
          description: "List discussion threads on a merge request, including each discussion's " \
            "resolution state, position, and notes."
        },
        {
          id: 100,
          name: "reply_to_discussion",
          title: "Reply To Discussion",
          description: "Reply to an existing discussion thread on a merge request."
        },
        {
          id: 101,
          name: "set_discussion_resolved",
          title: "Set Discussion Resolved",
          description: "Set the resolved status of a discussion thread on a merge request."
        },
        {
          id: 102,
          name: "submit_mr_review",
          title: "Submit MR Review",
          description: "Submit a complete merge request review with inline diff comments, a review " \
            "verdict, and an optional summary note."
        },
        {
          id: 103,
          name: "fetch_glql_schema",
          title: "Fetch GLQL Schema",
          description: "Get the GLQL schema served by this GitLab instance."
        },
        {
          id: 104,
          name: "post_suggested_reviewers",
          title: "Post Suggested Reviewers",
          description: "Persist AI-suggested reviewers for a merge request, replacing any " \
            "suggestions already stored. Suggestions are stored only; no reviewer is assigned."
        },
        {
          id: 105,
          name: "notify_me_when",
          title: "Notify Me When",
          description: "Set a condition for the agent to resume."
        }
      ].freeze
    end
  end
end
