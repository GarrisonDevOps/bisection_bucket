# frozen_string_literal: true

module Mcp
  module Tools
    module DuoWorkflows
      class ListDuoAgentsAndFlowsService < Base::GraphqlService
        include Availability

        ITEM_TYPES = [::Ai::Catalog::Item::AGENT_TYPE, ::Ai::Catalog::Item::FLOW_TYPE,
          ::Ai::Catalog::Item::THIRD_PARTY_FLOW_TYPE].map(&:to_s).freeze

        register_version '0.1.0', {
          toolset: :duo_agent_platform,
          description: <<~DESC.strip,
            List the GitLab Duo agents, flows and external agents enabled in a project, plus
            the project's foundational chat agents.

            Call this before start_duo_session rather than guessing a flow: the available
            agents and flows are configured per project, and their ids differ between
            projects.

            Each entry carries can_start_session, which is true for a flow you have permission to
            run, and for a foundational chat agent when you can run sessions in CI in this project.
            GitLab Duo itself, other agents and external agents are listed for discovery and are
            never startable, and a flow you cannot execute, or whose version is unreleased or still
            a draft, is listed as not startable too. Without GitLab Ultimate, a foundational chat
            agent that requires it is either left out or listed as not startable. Only startable
            flows carry the ai_catalog_item_consumer_id that start_duo_session takes; a foundational
            chat agent is started by passing its workflow_definition as agent.

            Items that are configured but disabled are dropped after the page is fetched,
            so a page can hold fewer entries than requested, or none at all, while
            pageInfo.hasNextPage is still true. Keep paging until hasNextPage is false
            instead of stopping at an empty page.

            The foundational chat agents are returned with the first page only, since they are
            a fixed list rather than part of the paginated project results. They are
            omitted unless agents are included, and they come in addition to first, so the
            first page can hold more entries than asked for. They are governed by the
            project's top-level group on GitLab.com and by the organization on GitLab
            Self-Managed, not by the project, and they carry a workflow_definition rather
            than an ai_catalog_item_consumer_id.
          DESC
          input_schema: {
            type: 'object',
            properties: {
              project_id: {
                type: 'string',
                description: 'Numeric ID or full path of the project to list agents and flows for.'
              },
              item_type: {
                type: 'string',
                description: 'Return only one kind of item. All kinds are returned when omitted.',
                enum: ITEM_TYPES
              },
              **Mcp::Tools::Concerns::CursorPagination.input_schema_params(items: 'agents and flows')
            },
            required: %w[project_id]
          },
          annotations: {
            title: 'List Duo agents and flows',
            readOnlyHint: true,
            idempotentHint: true,
            openWorldHint: false
          }
        }

        protected

        override :perform_default
        def perform_default(arguments = {})
          execute_graphql_tool(arguments)
        end

        private

        def graphql_tool_class
          Mcp::Tools::DuoWorkflows::ListDuoAgentsAndFlowsTool
        end
      end
    end
  end
end
