# frozen_string_literal: true

module Ai
  module FoundationalChatAgentsDefinitions
    extend ActiveSupport::Concern

    SYSTEM_PROMPTS_PATH = File.expand_path('foundational_chat_agents/system_prompts', __dir__)

    GITLAB_MAINTAINED = ::Namespaces::VerifiedNamespace::VERIFICATION_LEVELS[:gitlab_maintained]
    FOUNDATIONAL_AGENT_TYPE = Ai::Catalog::Item.item_types[Ai::Catalog::Item::FOUNDATIONAL_AGENT_TYPE]
    PUBLIC_VISIBILITY = Ai::Catalog::Item.visibilities[:public]
    PRIVATE_VISIBILITY = Ai::Catalog::Item.visibilities[:private]

    # coding_environment: 'none' only when every tool in the agent's AI Gateway flow config works
    # without a checkout; see doc/development/ai_features/foundational_chat_agents.md.
    ITEMS = [
      {
        id: 1,
        reference: 'chat',
        global_catalog_id: nil,
        version: '',
        flow_version: '^1.0.0',
        name: 'GitLab Duo',
        avatar: 'gitlab-duo-agent.png',
        visibility: PUBLIC_VISIBILITY,
        item_type: FOUNDATIONAL_AGENT_TYPE,
        verification_level: GITLAB_MAINTAINED,
        description: "Your general development assistant. Get help with code, planning,
        security, project management, and more."
      },
      {
        id: 2,
        reference: 'orbit_agent',
        version: 'v1',
        flow_version: '^1.0.0',
        name: 'Orbit',
        global_catalog_id: nil,
        avatar: 'gitlab-duo-agent.png',
        visibility: PUBLIC_VISIBILITY,
        item_type: Ai::Catalog::Item.item_types[Ai::Catalog::Item::FOUNDATIONAL_AGENT_TYPE],
        verification_level: ::Namespaces::VerifiedNamespace::VERIFICATION_LEVELS[:gitlab_maintained],
        description: <<~DESCRIPTION
          AI-powered intelligence analyst with Knowledge Graph access. Query your SDLC data as a connected graph to discover relationships between code, work items, merge requests, pipelines, vulnerabilities, and more.
        DESCRIPTION
      },
      {
        id: 3,
        reference: 'duo_planner',
        version: 'v1',
        name: 'Planner',
        global_catalog_id: 348,
        avatar: 'planner-agent.png',
        visibility: PUBLIC_VISIBILITY,
        item_type: FOUNDATIONAL_AGENT_TYPE,
        verification_level: GITLAB_MAINTAINED,
        tools: %i[
          gitlab_milestone_search
          gitlab__user_search
          gitlab_documentation_search
          get_current_user
          get_work_item
          create_work_item_note
          update_work_item
          list_work_items
          get_work_item_notes
          create_work_item
          get_wiki_page
        ],
        description: <<~DESCRIPTION
          Get help with planning and workflow management. Organize, edit, create, and track work more effectively in GitLab.
        DESCRIPTION
      },
      {
        id: 4,
        global_catalog_id: 356,
        reference: 'security_analyst_agent',
        version: 'v1',
        name: 'Security Analyst',
        avatar: 'security-agent.png',
        ultimate_only: true,
        visibility: PUBLIC_VISIBILITY,
        item_type: FOUNDATIONAL_AGENT_TYPE,
        verification_level: GITLAB_MAINTAINED,
        tools: %i[
          gitlab_commit_search
          create_issue
          create_issue_note
          create_merge_request
          create_merge_request_note
          edit_file
          get_commit
          get_commit_diff
          get_issue
          get_merge_request
          get_project
          get_repository_file
          grep
          list_all_merge_request_notes
          list_dir
          list_merge_request_diffs
          gitlab_merge_request_search
          read_file
          run_command
          update_issue
          update_merge_request
          create_file_with_contents
          create_vulnerability_issue
          read_files
          revert_to_detected_vulnerability
          update_vulnerability_severity
          link_vulnerability_to_issue
          get_vulnerability_details
          dismiss_vulnerability
          confirm_vulnerability
          create_commit
          list_vulnerabilities
          get_security_finding_details
          list_security_findings
          start_flow
        ],
        description: <<~DESCRIPTION
          Automate vulnerability management and security workflows. The Security Analyst Agent acts as an
          AI team member that can autonomously analyze,
          triage, and remediate security vulnerabilities, reducing manual security tasks while ensuring
          critical exploitable vulnerabilities are immediately surfaced and addressed.
        DESCRIPTION
      },
      {
        id: 5,
        reference: 'analytics_agent',
        global_catalog_id: 1003596,
        version: 'v1',
        flow_version: '^2.0.0',
        coding_environment: 'none',
        name: 'Data Analyst',
        avatar: 'analytics-agent.png',
        visibility: PUBLIC_VISIBILITY,
        item_type: FOUNDATIONAL_AGENT_TYPE,
        verification_level: GITLAB_MAINTAINED,
        tools: %i[
          create_merge_request_note
          get_current_user
          fetch_glql_schema
          create_work_item_note
          run_glql_query
        ],
        suggested_questions: [
          'How many merge requests were merged in the last 30 days?',
          'Which issues have been open the longest?',
          'How many issues were closed this month?',
          'Which of my merge requests are still open?',
          'What issues are assigned to me right now?',
          'Which open issues have no assignee?',
          'What merge requests am I reviewing?',
          'Which issues were created this week?'
        ],
        description: <<~DESCRIPTION
          Get help analyzing your GitLab data (powered by GLQL)
        DESCRIPTION
      },
      {
        id: 6,
        reference: 'ci_expert_agent',
        global_catalog_id: 1004583,
        version: 'v1',
        name: 'CI Expert',
        visibility: PUBLIC_VISIBILITY,
        item_type: FOUNDATIONAL_AGENT_TYPE,
        verification_level: GITLAB_MAINTAINED,
        tools: %i[
          gitlab_blob_search
          ci_linter
          create_merge_request
          edit_file
          find_files
          get_job_logs
          get_pipeline_errors
          get_project
          get_repository_file
          grep
          list_dir
          read_file
          create_file_with_contents
          gitlab_documentation_search
          read_files
          create_commit
          get_pipeline_failing_jobs
        ],
        description: <<~DESCRIPTION
          Helps you create, debug, and optimize GitLab CI/CD pipelines. This agent can generate
          .gitlab-ci.yml configurations, explain CI/CD syntax, suggest templates based on your
          project type, and recommend best practices for caching, parallelization, and pipeline efficiency.
        DESCRIPTION
      },
      {
        id: 7,
        reference: 'duo_permissions_assistant',
        version: 'v1',
        flow_version: '^2.0.0',
        coding_environment: 'none',
        name: 'Permissions Assistant',
        global_catalog_id: nil,
        visibility: PUBLIC_VISIBILITY,
        item_type: FOUNDATIONAL_AGENT_TYPE,
        verification_level: GITLAB_MAINTAINED,
        avatar: 'gitlab-duo-agent.png',
        selectable_in_chat: false,
        # The set_form_permissions tool is applied client-side, so it is intentionally
        # absent from this catalog tools list.
        tools: %i[
          gitlab_graphql
        ],
        description: <<~DESCRIPTION
          Get help with selecting permissions for fine-grained access tokens, applying the principle of least privilege.
        DESCRIPTION
      },
      {
        id: 8,
        reference: 'support_assistant',
        version: 'v1',
        name: 'Support Assistant',
        global_catalog_id: 1005590,
        avatar: 'gitlab-duo-agent.png',
        visibility: PUBLIC_VISIBILITY,
        item_type: Ai::Catalog::Item.item_types[Ai::Catalog::Item::FOUNDATIONAL_AGENT_TYPE],
        verification_level: ::Namespaces::VerifiedNamespace::VERIFICATION_LEVELS[:gitlab_maintained],
        description: <<~DESCRIPTION
          Your GitLab Support debugging buddy. Get help diagnosing GitLab product issues, finding relevant documentation, and preparing support tickets with the right diagnostic data.
        DESCRIPTION
      },
      # `agentic_chat/v1` workflow is going to replace `chat` workflow. See https://gitlab.com/groups/gitlab-org/-/work_items/19647
      {
        id: 9,
        reference: 'agentic_chat',
        version: 'v1',
        name: 'GitLab Duo',
        global_catalog_id: nil,
        visibility: PRIVATE_VISIBILITY,
        item_type: FOUNDATIONAL_AGENT_TYPE,
        verification_level: GITLAB_MAINTAINED,
        avatar: 'gitlab-duo-agent.png',
        selectable_in_chat: false,
        description: "Your general development assistant. Get help with code, planning,
        security, project management, and more."
      },
      {
        id: 10,
        reference: 'onboarding_guide',
        global_catalog_id: 1003979,
        version: 'v1',
        name: 'Onboarding agent (experimental)',
        visibility: PUBLIC_VISIBILITY,
        item_type: FOUNDATIONAL_AGENT_TYPE,
        verification_level: GITLAB_MAINTAINED,
        suggested_questions: [
          'We just bought GitLab. Where should my team start?',
          'What GitLab setup steps do you recommend for this project?',
          'Which GitLab features should I adopt first?',
          'I just moved from GitHub. How do I get started in GitLab?',
          'We use Jenkins. What does moving to GitLab CI/CD involve?',
          'How do I set up my first CI/CD pipeline in GitLab?',
          'How do I turn on security scanning in GitLab?',
          'How is this project organized, and how do I contribute?',
          'How should my team plan work with epics and issues?',
          'How do I get my team started with GitLab Duo?'
        ],
        description: <<~DESCRIPTION
          Personalized, tier-aware GitLab onboarding, from first repo import through DevSecOps adoption.
        DESCRIPTION
      },
      {
        id: 11,
        reference: 'flow_creator',
        version: 'v1',
        flow_version: '^1.0.0',
        coding_environment: 'none',
        name: 'Flow Creator',
        global_catalog_id: nil,
        visibility: PRIVATE_VISIBILITY,
        item_type: FOUNDATIONAL_AGENT_TYPE,
        verification_level: GITLAB_MAINTAINED,
        avatar: 'gitlab-duo-agent.png',
        description: <<~DESCRIPTION
          Create custom flows from chat. Describe the flow you want and get complete flow YAML for the AI Catalog.
        DESCRIPTION
      }
    ].freeze
  end
end
