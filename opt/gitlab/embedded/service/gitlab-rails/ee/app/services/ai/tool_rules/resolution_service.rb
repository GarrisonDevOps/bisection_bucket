# frozen_string_literal: true

module Ai
  module ToolRules
    class ResolutionService
      include ::Gitlab::Utils::StrongMemoize

      PRIVILEGE_GROUP_TO_CONSTANT = {
        read_only_gitlab: ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB,
        read_only_files: ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_FILES,
        read_write_gitlab: ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_GITLAB,
        read_write_files: ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_FILES,
        run_commands: ::Ai::DuoWorkflows::Workflow::AgentPrivileges::RUN_COMMANDS,
        use_git: ::Ai::DuoWorkflows::Workflow::AgentPrivileges::USE_GIT,
        run_mcp_tools: ::Ai::DuoWorkflows::Workflow::AgentPrivileges::RUN_MCP_TOOLS
      }.freeze

      def initialize(namespace:, surface:, project: nil, rules: nil)
        raise ArgumentError, 'surface is required' if surface.nil?

        @namespace = namespace
        @surface = surface
        @project = project
        @rules = rules
      end

      # @return [ServiceResponse] the allow, ask and deny lists and the first-party tool
      #   verdicts for the surface, or an error when the surface is ungoverned
      def execute
        surface_error = unresolvable_surface_error
        return surface_error if surface_error

        rules = effective_rules

        agent_privileges = []
        pre_approved_agent_privileges = []
        pre_approved_tools = []
        denied_tools = []
        ask_tools = []

        # Walk every mapped group, not just those with a privilege constant, so a rule on a
        # constant-less group like agent_internal is enforced instead of silently skipped.
        ::Ai::ToolRules::Registry::PRIVILEGE_GROUP_MAPPING.each_key do |group|
          constant = PRIVILEGE_GROUP_TO_CONSTANT[group]
          fallback = fallback_permission(group)
          denied_tools.concat(explicitly_configured_tools_for_group(group, rules, Permissions::DENY))
          pre_approved_tools.concat(explicitly_configured_tools_for_group(group, rules, Permissions::ALLOW))
          ask_tools.concat(explicitly_configured_tools_for_group(group, rules, Permissions::ASK))
          # Listed by name, not only dropped with the privilege: a partly ruled group keeps its
          # privilege, and a tool's MCP spelling is reached only through denied_tools.
          denied_tools.concat(unset_tools_for_group(group, rules)) if fallback == :deny

          # MCP names are absent from the catalog mapping resolve_group reads, so an MCP
          # rule can neither swing a group verdict nor count towards its quorum.
          case resolve_group(group, rules, fallback)
          when :deny
            next
          when :ask
            agent_privileges << constant if constant
            # The group loses its blanket pre-approval, but tools that still resolve to
            # allow keep theirs. Otherwise one ask rule silently demotes every tool the
            # admin left at a default of allow, which the settings page still shows as allow.
            pre_approved_tools.concat(allowed_tools_for_group(group, rules, fallback))
          when :allow
            if constant
              agent_privileges << constant
              pre_approved_agent_privileges << constant
            end

            pre_approved_tools.concat(allowed_tools_for_group(group, rules, fallback))
          end
        end

        # Belong to no privilege group, so the loop above never reaches them, and they take
        # no group fallback: an unruled MCP tool keeps whatever its annotations gave it.
        denied_tools.concat(explicitly_configured_mcp_tools(mcp_tools, rules, Permissions::DENY))
        pre_approved_tools.concat(explicitly_configured_mcp_tools(mcp_tools, rules, Permissions::ALLOW))
        ask_tools.concat(explicitly_configured_mcp_tools(mcp_tools, rules, Permissions::ASK))
        denied_tools.concat(unset_mcp_tools_failing_closed(mcp_tools, rules)) if fail_closed?

        # Kept out of every privilege group and therefore out of every group quorum. Only a
        # deny is mirrored: a DWS without first_party_tools support would read an allowed name
        # as pre-approved for any client tool of that name, and an asked one as governed away.
        first_party_tools = first_party_tool_verdicts(rules)
        denied_tools.concat(tools_with_verdict(first_party_tools, Permissions::DENY))

        agent_privileges << ::Ai::DuoWorkflows::Workflow::AgentPrivileges::START_FLOWS
        pre_approved_agent_privileges << ::Ai::DuoWorkflows::Workflow::AgentPrivileges::START_FLOWS

        # Two catalog rules can share one MCP spelling, so the most restrictive verdict
        # must win per emitted name as well, not only per rule.
        denied = emit(denied_tools, mcp_tools)
        asked = emit(ask_tools, mcp_tools) - denied
        allowed = emit(pre_approved_tools, mcp_tools, twins: false) - denied - asked

        ServiceResponse.success(payload: {
          agent_privileges: agent_privileges,
          pre_approved_agent_privileges: pre_approved_agent_privileges,
          pre_approved_tools: allowed,
          denied_tools: denied,
          ask_tools: asked,
          first_party_tools: first_party_tools,
          default_ask_tools: default_ask_tools(rules, mcp_tools, [denied, asked, allowed])
        })
      end

      # Where a project rule exists, most restrictive wins, projects can only escalate,
      # never loosen a namespace-level policy.
      # Guarded separately from #execute so a direct caller cannot skip the surface check.
      def effective_rules
        if ungoverned_surface?
          track_ungoverned_surface!
          return {}
        end

        if refused_surface?
          track_refused_surface!
          return {}
        end

        merge_rules(namespace_rules, project_rules)
      end
      strong_memoize_attr :effective_rules

      def permission_for(tool_name)
        explicit_permission_for(tool_name) || default_permission_for(tool_name)
      end

      def explicit_permission_for(tool_name)
        return refused_permission if refused_surface?

        governing_names(tool_name)
          .filter_map { |name| rule_permission(name) }
          .max_by { |permission| Permissions::RESTRICTIVENESS.fetch(permission.to_s, -1) }
      end

      # The first-party verdicts alone, for a session that is otherwise ungoverned: DWS still
      # needs the admin's rule there. Construct with the local surface, not UNGOVERNED.
      def first_party_verdicts
        return {} if first_party_tools.empty?

        first_party_tool_verdicts(effective_rules)
      end

      private

      def mcp_tools
        ::Ai::ToolRules::GovernedMcpTools.for(@namespace)
      end
      strong_memoize_attr :mcp_tools

      def first_party_tools
        ::Ai::ToolRules::FirstPartyTools.for(@namespace)
      end
      strong_memoize_attr :first_party_tools

      def namespace_rules
        return ::Ai::ToolRule.for_namespace(@namespace.id).index_by(&:tool_name) unless @rules

        @rules.select { |rule| rule.project_id.nil? }.index_by(&:tool_name)
      end

      def project_rules
        return {} unless @project
        return ::Ai::ToolRule.for_project(@project.id).index_by(&:tool_name) unless @rules

        @rules.select { |rule| rule.project_id == @project.id }.index_by(&:tool_name)
      end

      def governing_names(tool_name)
        [tool_name, *mcp_tools.identities_for(tool_name)].uniq
      end

      def default_permission_for(tool_name)
        default_names(tool_name)
          .map { |name| ::Ai::ToolRules::Registry.default_permission_of(name, **catalogs) }
          .max_by { |permission| Permissions::RESTRICTIVENESS.fetch(permission.to_s, -1) }
      end

      def catalogs
        { mcp_tools: mcp_tools, first_party_tools: first_party_tools }
      end

      def default_names(tool_name)
        mcp_tools.identities_for(tool_name).presence || [tool_name]
      end

      def rule_permission(tool_name)
        effective_rules[tool_name]&.access_for(@surface)
      end

      # Merges namespace and project rules, applying most-restrictive-wins per tool.
      # Note: Hash#merge with a block only fires for keys present in both hashes.
      # Keys only in project_rules (no matching namespace rule) are added as-is from the project.
      def merge_rules(namespace_rules, project_rules)
        return namespace_rules if project_rules.empty?

        if fail_closed?
          project_rules = project_rules.reject do |tool_name, rule|
            loosens_fail_closed?(tool_name, namespace_rules[tool_name], rule)
          end
        end

        namespace_rules.merge(project_rules) do |_tool_name, ns_rule, proj_rule|
          most_restrictive_rule(ns_rule, proj_rule)
        end
      end

      # Returns the more restrictive of two rules for the current surface.
      # Projects cannot loosen a namespace-level policy.
      def most_restrictive_rule(ns_rule, proj_rule)
        ns_permission = ns_rule.access_for(@surface)
        proj_permission = proj_rule.access_for(@surface)

        # If namespace has no value for this surface, project rule can set it freely.
        return proj_rule if ns_permission.nil?

        # If project has no value for this surface, keep the namespace rule.
        return ns_rule if proj_permission.nil?

        ns_score = Permissions::RESTRICTIVENESS[ns_permission.to_s]
        proj_score = Permissions::RESTRICTIVENESS[proj_permission.to_s]

        proj_score > ns_score ? proj_rule : ns_rule
      end

      def resolve_group(group, rules, fallback)
        governed = ::Ai::ToolRules::Registry.governed_tool_names_for(group_name: group)

        permissions = governed.filter_map do |tool_name|
          rules[tool_name]&.access_for(@surface)
        end

        # Tools without an explicit value for this surface keep the group default, so
        # a partial `allow` cannot pre-approve tools an admin never configured, and a
        # partial `deny` cannot make the whole group unavailable either.
        permissions << fallback.to_s if permissions.size < governed.size

        return fallback if permissions.empty?
        return :deny if permissions.all?(Permissions::DENY)
        return :allow if permissions.all?(Permissions::ALLOW)

        :ask
      end

      def ungoverned_surface?
        ::Ai::ToolRules::GovernanceSurface.ungoverned?(@surface)
      end

      # Loud in dev and test, tracked in production. Callers should never get here.
      def track_ungoverned_surface!
        ::Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
          ArgumentError.new(
            'ResolutionService received an ungoverned surface; check GovernanceSurface.ungoverned? first'
          ),
          namespace_id: @namespace&.id
        )
      end

      def ungoverned_surface_error
        ServiceResponse.error(message: 'Surface is ungoverned', reason: :ungoverned_surface)
      end

      def refused_surface?
        ::Ai::ToolRules::GovernanceSurface.refused?(@surface)
      end

      def track_refused_surface!
        ::Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
          ArgumentError.new('ResolutionService received a refused surface; deny the caller before resolving'),
          namespace_id: @namespace&.id
        )
      end

      def refused_permission
        track_refused_surface!
        Permissions::DENY
      end

      def refused_surface_error
        ServiceResponse.error(message: 'Surface is refused', reason: :refused_surface)
      end

      def unresolvable_surface_error
        if ungoverned_surface?
          track_ungoverned_surface!
          ungoverned_surface_error
        elsif refused_surface?
          track_refused_surface!
          refused_surface_error
        end
      end

      def fallback_permission(group)
        permission = ::Ai::ToolRules::Registry.default_permission_for(group_name: group)

        # Reached only when the background-governance flag is on.
        if background_surface?
          # run_mcp_tools has no catalog tools, so a deny here would drop the privilege that
          # pre-approves read-only MCP tools; MCP tools fail closed one by one instead.
          permission = ::Ai::ToolRules::Permissions.background_effective(
            permission, fail_closed: fail_closed? && group != :run_mcp_tools
          )
        end

        permission.to_sym
      end

      def background_surface?
        @surface.to_s == ::Ai::ToolRules::GovernanceSurface::BACKGROUND.to_s
      end

      # @return [Boolean] whether this background session denies un-ruled write and execute tools
      def fail_closed?
        background_surface? && ::Ai::ToolRules::GovernanceSurface.background_fail_closed?(@namespace)
      end
      strong_memoize_attr :fail_closed?

      # @param group [Symbol] a privilege group
      # @param rules [Hash{String => Ai::ToolRule}]
      # @return [Array<String>] the group's tools with no rule for this surface
      def unset_tools_for_group(group, rules)
        ::Ai::ToolRules::Registry.governed_tool_names_for(group_name: group).select do |tool_name|
          rules[tool_name]&.access_for(@surface).nil?
        end
      end

      # @param mcp_tools [Ai::ToolRules::GovernedMcpTools]
      # @param rules [Hash{String => Ai::ToolRule}]
      # @return [Array<String>] un-ruled MCP-only tools that fail-closed denies
      def unset_mcp_tools_failing_closed(mcp_tools, rules)
        mcp_tools.rulable_names.select do |tool_name|
          rules[tool_name]&.access_for(@surface).nil? &&
            ::Ai::ToolRules::GovernanceSurface.fail_closed_denies?(
              tool_name, mcp_tools: mcp_tools, first_party_tools: first_party_tools
            )
        end
      end

      # @param tool_name [String]
      # @param ns_rule [Ai::ToolRule, nil]
      # @param proj_rule [Ai::ToolRule]
      # @return [Boolean] whether the project rule allows a tool the group's fail-closed default denies
      def loosens_fail_closed?(tool_name, ns_rule, proj_rule)
        ns_rule&.access_for(@surface).nil? &&
          proj_rule.access_for(@surface) == Permissions::ALLOW &&
          ::Ai::ToolRules::GovernanceSurface.fail_closed_denies?(
            tool_name, mcp_tools: mcp_tools, first_party_tools: first_party_tools
          )
      end

      def allowed_tools_for_group(group, rules, fallback)
        ::Ai::ToolRules::Registry.governed_tool_names_for(group_name: group).select do |tool_name|
          rule = rules[tool_name]
          permission = rule ? rule.access_for(@surface) : fallback.to_s

          # No value for this surface falls back to the group default, so enforcement
          # matches the displayed default and another surface's rule can't demote it here.
          permission = fallback.to_s if permission.nil?

          permission == Permissions::ALLOW
        end
      end

      def default_ask_tools(rules, mcp_tools, settled_lists)
        unset = ::Ai::ToolRules::Registry::PRIVILEGE_GROUP_MAPPING.each_key.flat_map do |group|
          fallback_permission(group) == :ask ? unset_tools_for_group(group, rules) : []
        end

        emit(unset, mcp_tools, twins: false) - settled_lists.flatten
      end

      # @param twins [Boolean] see {Ai::ToolRules::Registry.to_mcp_tool_names}
      def emit(tool_names, mcp_tools, twins: true)
        ::Ai::ToolRules::Registry.to_mcp_tool_names(tool_names.uniq, mcp_tools: mcp_tools, twins: twins)
      end

      def explicitly_configured_mcp_tools(mcp_tools, rules, permission)
        mcp_tools.rulable_names.select do |tool_name|
          rules[tool_name]&.access_for(@surface) == permission
        end
      end

      def first_party_tool_verdicts(rules)
        first_party_tools.names.index_with do |tool_name|
          rules[tool_name]&.access_for(@surface) || first_party_fallback(tool_name)
        end
      end

      # Mirrors fallback_permission so the enforced default matches the displayed one.
      def first_party_fallback(tool_name)
        permission = ::Ai::ToolRules::Registry.default_permission_of(tool_name, first_party_tools: first_party_tools)
        background_surface? ? ::Ai::ToolRules::Permissions.background_effective(permission) : permission
      end

      def tools_with_verdict(verdicts, permission)
        verdicts.filter_map { |tool_name, verdict| tool_name if verdict == permission }
      end

      def explicitly_configured_tools_for_group(group, rules, permission)
        ::Ai::ToolRules::Registry.governed_tool_names_for(group_name: group).select do |tool_name|
          rule = rules[tool_name]
          next false unless rule

          rule.access_for(@surface) == permission
        end
      end
    end
  end
end
