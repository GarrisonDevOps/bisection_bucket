# frozen_string_literal: true

module Resolvers
  module Ai
    module DuoWorkflows
      class ToolAccessPoliciesResolver < BaseResolver
        type GraphQL::Types::JSON, null: true

        argument :project_id, ::Types::GlobalIDType[::Project],
          required: false,
          description: 'Global ID of the project the session runs in. It can only make the policy stricter.'

        alias_method :workflow, :object

        def resolve(project_id: nil)
          requested_project = ::Project.without_deleted.not_hidden.find_by_id(project_id.model_id) if project_id
          if requested_project && !Ability.allowed?(current_user, :read_project, requested_project)
            requested_project = nil
          end

          mcp_config_service = ::Ai::DuoWorkflows::McpConfigService.new(
            current_user,
            nil,
            workflow_definition: workflow.workflow_definition,
            ai_catalog_item_version_id: workflow.ai_catalog_item_version_id
          )

          ::Ai::DuoWorkflows::ToolAccessPoliciesService.new(
            workflow: workflow,
            root_namespace: nil,
            project: requested_project,
            environment: nil,
            mcp_config_service: mcp_config_service
          ).execute
        end
      end
    end
  end
end
