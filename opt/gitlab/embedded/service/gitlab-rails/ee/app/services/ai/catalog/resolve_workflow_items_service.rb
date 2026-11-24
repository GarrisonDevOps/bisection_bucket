# frozen_string_literal: true

module Ai
  module Catalog
    # Resolves the saved AI Catalog flow a Duo Workflow session runs, with the
    # agents its include entries reference, for the user who started it.
    # DWS gets the result from the GET catalog_items request, which it sends
    # through the Workhorse HTTP request action with the workflow's token.
    class ResolveWorkflowItemsService
      include Gitlab::Utils::StrongMemoize

      # Versions the shape of this payload. Workhorse passes the response to DWS
      # without changes, so DWS gets this number. Bump it when the payload
      # changes in a way an older DWS cannot read.
      SCHEMA_VERSION = 1

      FEATURE_FLAG_DISABLED = 'feature_flag_disabled'
      BETA_FEATURES_DISABLED = 'beta_features_disabled'

      def initialize(workflow:, current_user:)
        @workflow = workflow
        @current_user = current_user
      end

      def execute
        return missing_item_error unless item_version && project && item_version.item.flow?
        return root_item_not_readable_error unless readable_root_item?

        item = root_item
        Tracking::WorkflowItemsResolutionRecorder.new(
          workflow: workflow, current_user: current_user, root_item: item
        ).execute

        ServiceResponse.success(payload: { schema_version: SCHEMA_VERSION, item: item })
      end

      private

      attr_reader :workflow, :current_user

      def missing_item_error
        ServiceResponse.error(
          message: s_('AICatalog|This session does not run a saved AI Catalog flow'),
          reason: :missing_catalog_item_version
        )
      end

      # The user could read the flow when the session was created. It may have
      # been deleted or hidden since, and a resumed session reconnects later.
      def root_item_not_readable_error
        ServiceResponse.error(
          message: s_('AICatalog|The AI Catalog flow this session runs was not found or you do not have access to it'),
          reason: :root_item_not_readable
        )
      end

      def readable_root_item?
        item = item_version.item

        !item.deleted? && Ability.allowed?(current_user, :read_ai_catalog_item, item)
      end

      def root_item
        item_node(item_version.item, item_version).merge(
          definition_kind: 'inline',
          definition: item_version.flow_config,
          sub_items: sub_items,
          sub_items_skipped_reason: sub_items_skipped_reason
        )
      end

      def sub_items
        return [] if sub_items_skipped_reason

        dependencies.map { |dependency| sub_item(dependency) }
      end

      def sub_items_skipped_reason
        return FEATURE_FLAG_DISABLED unless Feature.enabled?(:ai_catalog_flow_agent_references, project)

        return if ::Gitlab::Llm::StageCheck.available?(project, :ai_catalog_flow_agent_references)

        BETA_FEATURES_DISABLED
      end
      strong_memoize_attr :sub_items_skipped_reason

      def sub_item(dependency)
        item = dependency.dependency
        version = dependency.dependency_version
        code = checks.refusal_code(item, version)
        code ||= :custom_agents_disabled if item.custom_agent_disabled_for?(project.root_ancestor)

        return refused_item(item, version, code) if code

        item_node(item, version).merge(definition_kind: 'inline', definition: agent_definition(item, version))
      end

      # An agent the user cannot read gets only what the flow's own include
      # entry already shows: its id and version. Any other refusal is of an
      # agent the user can read, so its name stays in the response.
      def refused_item(item, version, code)
        node = { item_type: item.item_type, item_id: item.id.to_s, version: version&.version }
        node = node.merge(name: item.name, description: item.description) unless code == :unknown_item

        node.merge(error: refusal(code, node))
      end

      # Called for the root flow and for a sub-agent that passed every check, so
      # the version is always present here. A refused sub-agent goes through
      # refused_item, which allows a nil version.
      def item_node(item, version)
        {
          item_type: item.item_type,
          item_id: item.id.to_s,
          version: version.version,
          name: item.name,
          description: item.description
        }
      end

      def agent_definition(item, version)
        definition = Ai::Catalog::AgentDefinition.new(item, version)

        { prompt: definition.system_prompt, toolset: definition.tool_names, mcp_tools: [] }
      end

      def refusal(code, node)
        message = Flows::ReferenceChecks.refusal_message(
          code, id: node[:item_id], version: node[:version], name: node[:name]
        )

        { code: code, message: message }
      end

      def dependencies
        rows = Ai::Catalog::ItemVersionDependency.for_item_version(item_version).with_resolved_dependencies
        namespaces = rows.map { |row| row.dependency.project&.namespace }
        Namespaces::Preloaders::NamespaceRootAncestorPreloader.new(namespaces).execute
        rows
      end
      strong_memoize_attr :dependencies

      def checks
        Flows::ReferenceChecks.new(
          user: current_user, flow_project: project, flow_visibility: item_version.item.visibility
        )
      end
      strong_memoize_attr :checks

      def item_version
        workflow.ai_catalog_item_version
      end

      def project
        workflow.project
      end
    end
  end
end
