# frozen_string_literal: true

module Mutations
  module Ai
    module DuoWorkflows
      class UpdateWebSearch < BaseMutation # rubocop:disable Search/NamespacedClass -- not search infrastructure, web_search is a Duo Chat feature toggle
        graphql_name 'UpdateDuoWorkflowWebSearch'

        include ::Mutations::Ai::DuoWorkflows::RequiresIdentityVerification

        authorize :update_duo_workflow
        authorize_granular_token permissions: :update_duo_workflow, boundary: :user, boundary_type: :user

        argument :workflow_id,
          ::Types::GlobalIDType[::Ai::DuoWorkflows::Workflow],
          required: true,
          description: 'Global ID of the workflow to update.'

        argument :web_search_enabled,
          GraphQL::Types::Boolean,
          required: true,
          description: 'Whether web search should be enabled for the session.'

        field :workflow,
          Types::Ai::DuoWorkflows::WorkflowType,
          null: true,
          description: 'Updated workflow.'

        field :errors,
          [GraphQL::Types::String],
          null: false,
          description: 'Errors encountered during update.'

        def resolve(workflow_id:, web_search_enabled:)
          raise_resource_not_available_error! unless Feature.enabled?(:dap_web_search, current_user)

          workflow = ::Gitlab::Graphql::Lazy.force(find_object(id: workflow_id))

          raise_if_identity_verification_required!(workflow&.resource_parent)
          authorize!(workflow)

          result = ::Ai::DuoWorkflows::UpdateWebSearchService.new(
            workflow: workflow,
            web_search_enabled: web_search_enabled,
            current_user: current_user
          ).execute

          if result.success?
            { workflow: result.payload[:workflow], errors: [] }
          else
            { workflow: nil, errors: [result.message] }
          end
        end
      end
    end
  end
end
