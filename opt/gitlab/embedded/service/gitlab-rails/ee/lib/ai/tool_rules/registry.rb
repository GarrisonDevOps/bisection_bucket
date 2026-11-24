# frozen_string_literal: true

module Ai
  module ToolRules
    module Registry
      # Tool names are sourced from Ai::Catalog::BuiltInTool.
      # Tools in the catalog that are not mapped to a privilege group are skipped, they will
      # not appear in the governance UI or be subject to enforcement.
      #
      # MAINTENANCE: When a new tool is added to Ai::Catalog::BuiltInToolDefinitions, add it
      # to the appropriate privilege group below. If it is intentionally ungovernable (e.g. an
      # internal planning tool), leave it unmapped and it will be skipped automatically.
      PRIVILEGE_GROUP_MAPPING = {
        read_only_gitlab: %w[
          list_issues
          get_issue
          get_job_logs
          get_merge_request
          gitlab_merge_request_search
          list_merge_request_diffs
          list_all_merge_request_notes
          list_mr_discussions
          get_pipeline_failing_jobs
          get_downstream_pipelines
          get_failing_bridge_jobs
          get_project
          gitlab_group_project_search
          gitlab_issue_search
          gitlab_milestone_search
          gitlab__user_search
          gitlab_blob_search
          gitlab_commit_search
          gitlab_wiki_blob_search
          gitlab_note_search
          get_epic
          list_epics
          list_issue_notes
          get_issue_note
          get_repository_file
          get_repository_files
          list_repository_tree
          list_epic_notes
          get_commit
          list_commits
          get_commit_diff
          get_commit_comments
          list_instance_audit_events
          list_group_audit_events
          list_project_audit_events
          get_work_item
          list_work_items
          get_work_item_notes
          get_work_item_statuses
          get_vulnerability_details
          evaluate_vuln_fp_status
          get_session_context
          ci_linter
          get_current_user
          get_glql_schema
          fetch_glql_schema
          run_glql_query
          build_review_merge_request_context
          get_security_finding_details
          list_security_findings
          ascp_list_scans
          ascp_list_components
          get_wiki_page
          gitlab_documentation_search
          gitlab_api_get
          gitlab_graphql
          list_vulnerabilities
          extract_lines_from_text
          get_epic_note
          get_merge_request_conflicts
        ].freeze,

        read_only_files: %w[
          read_file
          read_files
          find_files
          list_dir
          grep
        ].freeze,

        read_write_gitlab: %w[
          create_issue
          update_issue
          create_issue_note
          create_merge_request
          create_merge_request_note
          create_merge_request_diff_note
          update_merge_request
          add_merge_request_reviewers
          post_suggested_reviewers
          submit_mr_review
          reply_to_discussion
          set_discussion_resolved
          create_epic
          update_epic
          create_commit
          create_branch
          create_work_item
          update_work_item
          create_work_item_note
          update_vulnerability_severity
          post_sast_fp_analysis_to_gitlab
          post_secret_fp_analysis_to_gitlab
          set_form_permissions
          ascp_create_scan
          ascp_create_component
          ascp_create_security_context
          dismiss_vulnerability
          confirm_vulnerability
          revert_to_detected_vulnerability
          create_vulnerability_issue
          link_vulnerability_to_issue
          link_vulnerability_to_merge_request
        ].freeze,

        read_write_files: %w[
          create_file_with_contents
          edit_file
          mkdir
          run_tests
        ].freeze,

        run_commands: %w[
          run_command
        ].freeze,

        use_git: %w[
          run_git_command
        ].freeze,

        # Tools that act only on the agent's own session. No workflow privilege grants these,
        # so the group has no AgentPrivileges constant; rules still apply per tool.
        agent_internal: %w[
          notify_me_when
        ].freeze,

        run_mcp_tools: [].freeze
      }.freeze

      # Tools that are intentionally not subject to governance rules.
      # Add a tool here only if it should not appear in the admin UI.
      UNGOVERNED_TOOLS = %w[
        get_pipeline_errors
        set_task_status
        add_new_task
        create_plan
        get_plan
        update_task_description
        remove_task
        start_flow
      ].freeze

      # Catalog tools whose capability the MCP server also serves under another catalog
      # tool's identity. Widens the MCP spellings a deny or ask reaches; it never renames
      # the rule, and an allow never follows it: the shared MCP tool also serves
      # capabilities the admin did not allow.
      MCP_CAPABILITY_TWIN = {
        'create_issue' => 'create_work_item'
      }.freeze

      REPLACEMENT_TOOL_FOR = { 'get_issue' => 'get_work_item' }.freeze

      # Tools a GitLab client serves to DWS from its own local MCP server, under the exact name
      # DWS sees. Not in a privilege group (as the sole run_mcp_tools member, an allow would
      # pre-approve every MCP tool) and not in the AI Catalog (custom agents could pick it).
      FIRST_PARTY_CLIENT_TOOLS = {
        # Reads the local checkout and writes nothing to GitLab, so it defaults to allow.
        'mcp__duo__review' => :read
      }.freeze

      FIRST_PARTY_CLIENT_TOOL_CATEGORY = 'Duo CLI'

      ACTION_TYPE_GROUPS = {
        read: %i[read_only_gitlab read_only_files agent_internal].freeze,
        write: %i[read_write_gitlab read_write_files].freeze,
        destroy: %i[run_commands run_mcp_tools use_git].freeze
      }.freeze

      CATEGORY_FOR_GROUP = {
        read_only_gitlab: 'GitLab Read',
        read_only_files: 'Files',
        read_write_gitlab: 'GitLab Write',
        read_write_files: 'Files',
        run_commands: 'Commands',
        use_git: 'Git',
        agent_internal: 'Agent',
        run_mcp_tools: 'MCP'
      }.freeze

      PRIVILEGE_GROUP_FOR = PRIVILEGE_GROUP_MAPPING.each_with_object({}) do |(group, tools), h|
        tools.each { |tool_name| h[tool_name] = group }
      end.freeze

      # Groups auto-approved (`allow`) when a namespace has no explicit rule: reads of
      # GitLab resources and the local filesystem, and agent_internal tools that touch
      # nothing outside the session. Write, delete and command tools still default to
      # `ask` (least privilege).
      #
      # Intentionally diverges from the pre_approved_agent_privileges column default
      # (`{1,2}` = read_write_files + read_only_gitlab) -- do not re-sync.
      DEFAULT_PREAPPROVED_GROUPS = %i[read_only_gitlab read_only_files agent_internal].freeze

      class << self
        def catalog_tool_names
          @catalog_tool_names ||= ::Ai::Catalog::BuiltInTool.all.map(&:name).freeze
        end

        # Tools in the catalog but not in PRIVILEGE_GROUP_MAPPING are skipped.
        def all_tool_names
          @all_tool_names ||= catalog_tool_names.select { |name| PRIVILEGE_GROUP_FOR.key?(name) }.freeze
        end

        # Mapped names without a catalog entry can never carry an Ai::ToolRule, so they
        # must not count toward "every tool in the group is explicitly configured".
        def governed_tool_names_for(group_name:)
          PRIVILEGE_GROUP_MAPPING.fetch(group_name, []) & all_tool_names
        end

        # Returns the default permission for a tool when no explicit rule exists.
        # For tools in DEFAULT_PREAPPROVED_GROUPS, returns Permissions::ALLOW.
        # For all other tools, returns Permissions::ASK.
        # When both `tool_name:` and `group_name:` are given, `group_name` takes precedence.
        def default_permission_for(tool_name: nil, group_name: nil)
          resolved_group = group_name || (tool_name && PRIVILEGE_GROUP_FOR[tool_name])
          return Permissions::ALLOW if resolved_group && DEFAULT_PREAPPROVED_GROUPS.include?(resolved_group)

          Permissions::ASK
        end

        # Reverse lookup: tool name -> action type symbol (:read, :write, or :destroy).
        def action_type_for
          @action_type_for ||= all_tool_names.each_with_object({}) do |tool_name, h|
            group = PRIVILEGE_GROUP_FOR[tool_name]
            ACTION_TYPE_GROUPS.each do |type, groups|
              h[tool_name] = type if groups.include?(group)
            end
          end.freeze
        end

        # Tool names grouped by whether they read or change something. Destroy tools change
        # things too, so every action type other than :read is 'write'. Not memoized, so
        # specs that stub all_tool_names or action_type_for see their subset here as well.
        #
        # @return [Hash{String => Array<String>}] 'read' and 'write' keys
        def tool_names_by_access
          action_type_for
            .group_by { |_name, type| type == :read ? 'read' : 'write' }
            .transform_values { |pairs| pairs.map(&:first) }
        end

        # 'mcp' for a tool the MCP server serves, a first-party client tool, or one in the
        # run_mcp_tools privilege group, 'gitlab' for everything else.
        def source_for(tool_name, mcp_tools: nil, first_party_tools: nil)
          return 'mcp' if mcp_governed?(tool_name, mcp_tools) || first_party?(tool_name, first_party_tools)

          PRIVILEGE_GROUP_FOR[tool_name] == :run_mcp_tools ? 'mcp' : 'gitlab'
        end

        # Catalog names pass through untouched, the Duo Workflow Service matches a rule by
        # exact string; only the prefixed MCP spellings are appended.
        #
        # @param catalog_names [Array<String>] tool names as stored on Ai::ToolRule
        # @param mcp_tools [Ai::ToolRules::GovernedMcpTools, nil]
        # @param twins [Boolean] false for an allow list, see {MCP_CAPABILITY_TWIN}
        # @return [Array<String>]
        def to_mcp_tool_names(catalog_names, mcp_tools: nil, twins: true)
          return catalog_names.dup if empty_catalog?(mcp_tools)

          # An MCP-only tool has no catalog identity, so only its prefixed spelling is
          # ever matched. Emitting the bare name as well would add weight to the JWT
          # that no consumer looks up.
          addressable = catalog_names.reject { |name| mcp_tools.rulable_names.include?(name) }
          twin_names = twins ? catalog_names.filter_map { |name| MCP_CAPABILITY_TWIN[name] } : []
          spellings = (catalog_names + twin_names).uniq.flat_map { |name| mcp_tools.spellings_for(name) }

          (addressable + spellings).uniq
        end

        # Deliberately not memoized, unlike all_tool_names: the MCP catalog is
        # request-scoped and flag-dependent, so caching it in a class ivar would serve
        # one namespace's answer to another.
        def rulable_tool_names(mcp_tools: nil, first_party_tools: nil)
          first_party_names = first_party_tools&.names || []
          return all_tool_names + first_party_names if empty_catalog?(mcp_tools)

          all_tool_names + first_party_names + mcp_tools.rulable_names
        end

        # The rule that governs a tool name recorded in an audit event. Events carry the
        # Duo Workflow Service's spelling, so a GitLab MCP tool arrives as `gitlab_<tool>`
        # and can be governed by a differently named rule through an alias.
        def governed_name_for(recorded_name, mcp_tools: nil, first_party_tools: nil)
          rulable = rulable_tool_names(mcp_tools: mcp_tools, first_party_tools: first_party_tools)
          return recorded_name if rulable.include?(recorded_name)
          return if empty_catalog?(mcp_tools)

          mcp_tools.rule_for_spelling(recorded_name)
        end

        def action_type_of(tool_name, mcp_tools: nil, first_party_tools: nil)
          return action_type_for[tool_name] if all_tool_names.include?(tool_name)
          return FIRST_PARTY_CLIENT_TOOLS.fetch(tool_name) if first_party?(tool_name, first_party_tools)
          return unless mcp_governed?(tool_name, mcp_tools)

          mcp_tools.action_type_for(tool_name)
        end

        # An MCP tool in no privilege group keeps what its annotations already earned it:
        # McpConfigService pre-approves the read-only ones, so anything else prompts.
        # Deriving it here keeps the displayed default equal to the enforced one.
        def default_permission_of(tool_name, mcp_tools: nil, first_party_tools: nil)
          group = PRIVILEGE_GROUP_FOR[tool_name] if all_tool_names.include?(tool_name)
          return default_permission_for(group_name: group) if group

          action_type = action_type_of(tool_name, mcp_tools: mcp_tools, first_party_tools: first_party_tools)
          return Permissions::ASK unless action_type == :read

          Permissions::ALLOW
        end

        def category_for(tool_name, mcp_tools: nil, first_party_tools: nil)
          return FIRST_PARTY_CLIENT_TOOL_CATEGORY if first_party?(tool_name, first_party_tools)

          # An MCP-only tool borrows the MCP group's category for display without
          # joining the group, which would pull it into group-level resolution.
          group = (PRIVILEGE_GROUP_FOR[tool_name] if all_tool_names.include?(tool_name)) ||
            (:run_mcp_tools if mcp_governed?(tool_name, mcp_tools))

          CATEGORY_FOR_GROUP[group]
        end

        private

        def empty_catalog?(mcp_tools)
          mcp_tools.nil? || mcp_tools.empty?
        end

        def mcp_governed?(tool_name, mcp_tools)
          return false if empty_catalog?(mcp_tools)

          mcp_tools.rulable_names.include?(tool_name)
        end

        def first_party?(tool_name, first_party_tools)
          return false if first_party_tools.nil?

          first_party_tools.include?(tool_name)
        end
      end
    end
  end
end
