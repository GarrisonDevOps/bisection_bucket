# frozen_string_literal: true

module Mutations
  module Ai
    class BulkUpdateAiToolRules < BaseMutation
      graphql_name 'BulkUpdateAiToolRules'
      description 'Bulk updates permission settings for multiple AI tool rules.'

      authorize :update_ai_tool_rule
      authorize_granular_token permissions: :update_ai_tool_rule,
        boundaries: [
          { boundary_argument: :full_path, boundary_type: :group },
          { boundary_argument: :project_path, boundary_type: :project }
        ]

      MAX_RULES = 100
      RATE_LIMIT_KEY = :ai_tool_rules_bulk_update

      argument :full_path, GraphQL::Types::ID,
        required: true,
        description: 'Full path of the root namespace to update tool rules for.'

      argument :project_path, GraphQL::Types::ID,
        required: false,
        description: 'Full path of the project to update tool rules for. ' \
          'When provided, rules can only be stricter than the namespace rule.'

      argument :tool_rules, [Types::Ai::BulkToolRuleInputType],
        required: true,
        validates: { length: { minimum: 1, maximum: MAX_RULES } },
        description: "Tool rules to update (maximum #{MAX_RULES} entries). Each entry replaces the whole rule, " \
          'so a partial entry clears the access types it omits.'

      field :results, [Types::Ai::BulkToolRuleResultType],
        null: false,
        description: 'Results for each tool rule update, including any per-item errors.'

      def resolve(full_path:, tool_rules:, project_path: nil)
        namespace = authorized_find!(full_path: full_path)

        check_rate_limit!

        project = project_path ? ::Project.find_by_full_path(project_path) : nil
        if project_path && (project.nil? || !Ability.allowed?(current_user, :read_project, project))
          raise_resource_not_available_error! "Project not accessible"
        end

        if project && project.root_namespace.id != namespace.id
          raise_resource_not_available_error! "Project does not belong to the namespace"
        end

        catalogs = {
          mcp_tools: ::Ai::ToolRules::GovernedMcpTools.for(namespace),
          first_party_tools: ::Ai::ToolRules::FirstPartyTools.for(namespace)
        }

        valid_inputs, error_results = partition_inputs(tool_rules, catalogs)
        changed_inputs = changed_inputs_for(valid_inputs, namespace, project)

        if changed_inputs.any?
          begin
            attributes = build_upsert_attributes(changed_inputs, namespace, project, catalogs)
            ::Ai::ToolRule.upsert_all(
              attributes,
              unique_by: [:namespace_id, :project_id, :tool_name],
              returning: false,
              on_duplicate: Arel.sql(<<~SQL.squish)
                web_access = excluded.web_access,
                local_access = excluded.local_access,
                background_access = excluded.background_access,
                updated_at = excluded.updated_at
              SQL
            )

            emit_bulk_audit_event(namespace, project, changed_inputs)
          rescue ActiveRecord::StatementInvalid => e
            Gitlab::ErrorTracking.track_exception(e, namespace_id: namespace.id)

            return {
              results: build_success_results(
                valid_inputs, namespace, project, catalogs, failed_tool_names: tool_ids(changed_inputs)
              ) + error_results,
              errors: ['Failed to save tool rules']
            }
          end
        end

        success_results = build_success_results(valid_inputs, namespace, project, catalogs)

        { results: success_results + error_results, errors: [] }
      end

      private

      # Rejects the call when the user is over the per-user limit and the flag is on.
      #
      # @raise [RateLimitedService::RateLimitedError]
      def check_rate_limit!
        return unless ::Feature.enabled?(:ai_tool_rules_bulk_update_rate_limit, current_user)
        return unless ::Gitlab::ApplicationRateLimiter.throttled?(RATE_LIMIT_KEY, scope: { user: current_user })

        raise ::RateLimitedService::RateLimitedError.new(
          key: RATE_LIMIT_KEY, rate_limiter: ::Gitlab::ApplicationRateLimiter
        ), ::Gitlab::ApplicationRateLimiter.throttled_error_message
      end

      def tool_ids(inputs)
        inputs.map { |i| i[:tool_id] } # rubocop:disable Rails/Pluck -- inputs is a Ruby array
      end

      def partition_inputs(tool_rules, catalogs)
        valid = []
        errors = []
        governed_names = ::Ai::ToolRules::Registry.rulable_tool_names(**catalogs)

        tool_rules.each do |input|
          if input[:web_access].nil? && input[:local_access].nil? && input[:background_access].nil?
            errors << {
              tool_id: input[:tool_id],
              tool_rule: nil,
              errors: ["At least one of web_access, local_access, or background_access must be provided"]
            }
            next
          end

          if governed_names.include?(input[:tool_id])
            valid << input
          else
            errors << {
              tool_id: input[:tool_id],
              tool_rule: nil,
              errors: ["#{input[:tool_id]} is not a known tool name"]
            }
          end
        end

        [valid, errors]
      end

      def build_upsert_attributes(inputs, namespace, project, catalogs)
        timestamp = Time.current
        inputs.map do |input|
          {
            namespace_id: namespace.id,
            project_id: project&.id,
            tool_name: input[:tool_id],
            web_access: input[:web_access],
            local_access: input[:local_access],
            background_access: input[:background_access],
            tool_source: ::Ai::ToolRules::Registry.source_for(input[:tool_id], **catalogs),
            created_at: timestamp,
            updated_at: timestamp
          }
        end
      end

      # Keeps the inputs that change or create a stored row, so a resend of matching values
      # writes no row and adds no audit entry. A tool named twice in one payload always counts
      # as changed, so the upsert rejects it as before instead of half of it being skipped.
      #
      # @param inputs [Array<Types::Ai::BulkToolRuleInputType>] the valid tool rule inputs
      # @param namespace [Namespace] the root namespace the rules belong to
      # @param project [Project, nil] the project scope, when given
      # @return [Array<Types::Ai::BulkToolRuleInputType>] the inputs that change a stored row or create one
      def changed_inputs_for(inputs, namespace, project)
        return [] if inputs.empty?

        # Scoped by namespace as well as project, matching the upsert's unique key, so a row left
        # behind by a project transfer cannot stand in for this namespace's row. A nil project id
        # selects the namespace-level rows.
        scope = ::Ai::ToolRule.within_namespace(namespace.id).for_project(project&.id)
        stored = scope.for_tool_names(tool_ids(inputs)).index_by(&:tool_name)
        repeated = tool_ids(inputs).tally.select { |_, count| count > 1 }

        inputs.select { |input| repeated.key?(input[:tool_id]) || !unchanged?(input, stored[input[:tool_id]]) }
      end

      # @param input [Types::Ai::BulkToolRuleInputType] one tool rule input
      # @param rule [Ai::ToolRule, nil] the stored row for that tool at this scope
      # @return [Boolean] true when every access value already matches the stored row
      def unchanged?(input, rule)
        return false unless rule

        ::Ai::ToolRules::Permissions::ACCESS_TYPES.all? { |type| rule[type] == input[type]&.to_s }
      end

      # Builds one result per input: a failure for the tools in `failed_tool_names`, a saved rule
      # for every other input, since a successful upsert writes every row it is given.
      #
      # @param failed_tool_names [Array<String>] tools whose upsert raised; empty after a successful write
      # @return [Array<Hash>]
      def build_success_results(inputs, namespace, project, catalogs, failed_tool_names: [])
        return [] if inputs.empty?

        namespace_rules = project ? namespace_rules_for(namespace, inputs) : {}
        fail_closed = ::Ai::ToolRules::GovernanceSurface.background_fail_closed?(namespace)

        inputs.map do |input|
          if failed_tool_names.include?(input[:tool_id])
            next { tool_id: input[:tool_id], tool_rule: nil, errors: ['Failed to save rule'] }
          end

          stored_rule = ::Ai::ToolRules::Permissions::ACCESS_TYPES.index_with { |type| input[type]&.to_s }

          {
            tool_id: input[:tool_id],
            tool_rule: ::Ai::ToolRules::ToolPresenter.tool_rule_for(
              input[:tool_id],
              namespace_rule: project ? namespace_rules[input[:tool_id]] : stored_rule,
              project_rule: project ? stored_rule : nil,
              project_scoped: project.present?,
              **catalogs,
              fail_closed: fail_closed
            ),
            errors: []
          }
        end
      end

      def namespace_rules_for(namespace, inputs)
        ::Ai::ToolRule.for_namespace(namespace.id).for_tool_names(tool_ids(inputs)).index_by(&:tool_name)
      end

      def emit_bulk_audit_event(namespace, project, inputs)
        tool_names = tool_ids(inputs).join(', ')

        ::Gitlab::Audit::Auditor.audit({
          name: 'ai_tool_rules_bulk_updated',
          author: current_user,
          scope: namespace,
          target: namespace,
          message: "Bulk updated #{inputs.size} AI tool rules: #{tool_names}",
          additional_details: {
            namespace_id: namespace.id,
            project_id: project&.id,
            tool_count: inputs.size,
            tool_names: tool_ids(inputs)
          }
        })
      end

      def find_object(full_path:, **_kwargs)
        namespace = ::Namespace.find_by_full_path(full_path)
        namespace&.root? ? namespace : nil
      end
    end
  end
end
