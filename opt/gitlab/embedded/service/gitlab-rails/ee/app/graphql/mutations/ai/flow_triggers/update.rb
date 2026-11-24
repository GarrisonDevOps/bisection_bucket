# frozen_string_literal: true

module Mutations
  module Ai
    module FlowTriggers
      class Update < BaseMutation
        graphql_name 'AiFlowTriggerUpdate'

        include ::Mutations::Ai::Catalog::ConfigValidationRateLimitable
        include ServiceResponsePayload

        authorize :manage_ai_flow_triggers
        authorize_granular_token permissions: :update_ai_flow_trigger,
          boundaries: [
            { boundary_argument: :id, boundary: :project, boundary_type: :project },
            { boundary_argument: :id, boundary: :group, boundary_type: :group }
          ]

        argument :id, ::Types::GlobalIDType[::Ai::FlowTrigger],
          required: true,
          description: 'ID of the flow trigger to update.'

        argument :user_id, ::Types::GlobalIDType[::User],
          prepare: ->(global_id, _ctx) { global_id&.model_id&.to_i },
          required: false,
          description: 'Service account for the AI flow trigger.'

        argument :description, GraphQL::Types::String,
          required: false,
          description: 'Description of the AI flow trigger.'

        argument :event_types, [GraphQL::Types::Int],
          required: false,
          description: 'Event types that triggers the AI flow.'

        argument :config_path, GraphQL::Types::String,
          required: false,
          description: 'Path to the configuration file for the AI flow trigger.'

        argument :ai_catalog_item_consumer_id, ::Types::GlobalIDType[::Ai::Catalog::ItemConsumer],
          prepare: ->(global_id, _ctx) { global_id&.model_id&.to_i },
          required: false,
          description: 'AI catalog item consumer to use instead of config_path.'

        argument :filter, GraphQL::Types::JSON, # rubocop:disable Graphql/JSONType -- filter schema is not model backend
          required: false,
          experiment: { milestone: '18.11' },
          description: 'Filter conditions for the AI flow trigger.'

        argument :goals, GraphQL::Types::JSON, # rubocop:disable Graphql/JSONType -- keyed by event type, not model backed
          required: false,
          experiment: { milestone: '19.5' },
          description: 'Goals for the AI flow trigger, keyed by event type.'

        argument :status_on_finish, GraphQL::Types::String,
          required: false,
          experiment: { milestone: '19.6' },
          description: copy_field_description(Types::Ai::FlowTriggerType, :status_on_finish)

        argument :ready_merge_requests_on_finish, GraphQL::Types::Boolean,
          required: false,
          validates: { allow_null: false },
          experiment: { milestone: '19.6' },
          description: copy_field_description(Types::Ai::FlowTriggerType, :ready_merge_requests_on_finish)

        argument :active, GraphQL::Types::Boolean,
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Indicates whether the AI flow trigger is active. Inactive triggers do not run automatically.'

        field :ai_flow_trigger,
          Types::Ai::FlowTriggerType,
          description: 'Updated AI flow trigger.'

        field :error_reason,
          Types::Ai::FlowTrigger::ErrorReasonEnum,
          null: true,
          experiment: { milestone: '19.6' },
          description: 'Machine-readable reason for the mutation error.'

        def resolve(id:, **params)
          trigger = authorized_find!(id: id)

          if config_validation_rate_limited?
            return { ai_flow_trigger: nil, errors: [config_validation_rate_limited_message] }
          end

          response = ::Ai::FlowTriggers::UpdateService.new(project: trigger.project,
            current_user: context[:current_user], trigger: trigger).execute(params)

          service_response_payload(response)
        end
      end
    end
  end
end
