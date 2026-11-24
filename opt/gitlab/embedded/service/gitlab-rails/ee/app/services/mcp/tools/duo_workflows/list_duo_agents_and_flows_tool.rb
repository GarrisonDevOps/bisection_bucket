# frozen_string_literal: true

module Mcp
  module Tools
    module DuoWorkflows
      class ListDuoAgentsAndFlowsTool < Mcp::Tools::Base::GraphqlTool
        include Gitlab::Utils::StrongMemoize
        include Mcp::Tools::Concerns::ResourceFinder
        include Mcp::Tools::Concerns::CursorPagination

        DESCRIPTION_PREVIEW_LIMIT = 200
        AGENT_TYPE = ::Ai::Catalog::Item::AGENT_TYPE.to_s.freeze
        STARTABLE_TYPE = ::Ai::Catalog::Item::FLOW_TYPE.to_s.freeze
        DUO_CHAT_DEFINITIONS = ::Ai::FoundationalChatAgent.only_duo_chat_agent.map(&:workflow_definition).freeze

        register_version VERSIONS[:v0_1_0], {
          graphql_operation: load_graphql('duo_workflows/list_duo_agents_and_flows.query.graphql'),
          operation_name: 'aiCatalogConfiguredItems'
        }

        def build_variables
          {
            projectId: project.to_global_id.to_s,
            itemTypes: item_types.map(&:upcase),
            includeChatAgents: include_chat_agents?,
            **resolve_pagination_direction
          }.compact
        end

        private

        def project
          find_project!(params[:project_id].to_s)
        end
        strong_memoize_attr :project

        def item_types
          params[:item_type].present? ? [params[:item_type]] : ListDuoAgentsAndFlowsService::ITEM_TYPES
        end

        # First page only: they are a fixed list, so a later page would repeat them.
        def include_chat_agents?
          item_types.include?(AGENT_TYPE) && params[:after].blank?
        end

        def process_result(result)
          processed_result = super
          return processed_result if processed_result[:isError]

          connection = processed_result[:structuredContent]
          consumers = connection['nodes']
          page_info = connection['pageInfo']
          return ::Mcp::Tools::Base::Response.error('Operation returned no data') unless consumers && page_info

          data = {
            'items' => consumer_items(consumers) + chat_agent_items(result),
            'pageInfo' => page_info
          }
          formatted_content = [{ type: 'text', text: Gitlab::Json.dump(data) }]

          ::Mcp::Tools::Base::Response.success(formatted_content, data)
        end

        def consumer_items(consumers)
          consumers.select { |consumer| consumer['enabled'] && consumer['item'].present? }
            .map { |consumer| item_data(consumer) }
            .reject { |item| foundational_agent?(item) }
        end

        # aiFoundationalChatAgents is the canonical source, on every instance type.
        def foundational_agent?(item)
          item['type'] == AGENT_TYPE && item['foundational']
        end

        def chat_agent_items(result)
          nodes = result.dig('data', 'aiFoundationalChatAgents', 'nodes') || []

          nodes.map do |agent|
            {
              'name' => agent['name'],
              'description' => agent['description'].truncate(DESCRIPTION_PREVIEW_LIMIT),
              'type' => AGENT_TYPE,
              'foundational' => true,
              'workflow_definition' => agent['referenceWithVersion'],
              'can_start_session' => agent_startable?(agent),
              'ai_catalog_item_consumer_id' => nil
            }
          end
        end

        def agent_startable?(agent)
          definition = agent['referenceWithVersion']

          DUO_CHAT_DEFINITIONS.exclude?(definition) &&
            agent_licensed?(definition) &&
            agent_sessions_allowed?(definition)
        end

        def agent_licensed?(definition)
          foundational_agent = ::Ai::FoundationalChatAgent.with_workflow_definition(definition)

          foundational_agent.nil? || foundational_agent.licensed_for?(project.root_ancestor)
        end

        # As in web chat, the project's CI settings do not apply to an agent that starts on Workhorse.
        def agent_sessions_allowed?(definition)
          return agentic_chat_allowed? if ::Ai::FoundationalChatAgent.mcp_workhorse_session?(definition, current_user)

          ci_sessions_allowed?
        end

        def agentic_chat_allowed?
          Ability.allowed?(current_user, :access_duo_agentic_chat, project)
        end
        strong_memoize_attr :agentic_chat_allowed?

        def ci_sessions_allowed?
          project.duo_remote_flows_enabled &&
            agentic_chat_allowed? &&
            Ability.allowed?(current_user, :duo_workflow, project)
        end
        strong_memoize_attr :ci_sessions_allowed?

        def item_data(consumer)
          item = consumer.fetch('item')
          consumer_id = GlobalID.parse(consumer.fetch('id')).model_id.to_i
          type = item.fetch('itemType').downcase
          startable = startable?(type, consumer)

          {
            'name' => item.fetch('name'),
            'description' => item.fetch('description').truncate(DESCRIPTION_PREVIEW_LIMIT),
            'type' => type,
            'foundational' => item['foundational'],
            'workflow_definition' => nil,
            'can_start_session' => startable,
            'ai_catalog_item_consumer_id' => (consumer_id if startable)
          }
        end

        def startable?(type, consumer)
          type == STARTABLE_TYPE && consumer.dig('userPermissions', 'executeAiCatalogItem')
        end
      end
    end
  end
end
