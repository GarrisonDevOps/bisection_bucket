# frozen_string_literal: true

module Mutations
  module Ai
    module FlowTriggers
      class Create < BaseMutation
        graphql_name 'AiFlowTriggerCreate'

        include FindsProject
        include ::Mutations::Ai::Catalog::ConfigValidationRateLimitable
        include ServiceResponsePayload

        authorize :manage_ai_flow_triggers
        authorize_granular_token permissions: :create_ai_flow_trigger,
          boundary_argument: :project_path, boundary_type: :project

        argument :project_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the project the AI flow trigger is associated with.'

        argument :user_id, ::Types::GlobalIDType[::User],
          prepare: ->(global_id, _ctx) { global_id&.model_id&.to_i },
          required: false,
          description: 'Service account for the AI flow trigger.'

        argument :description, GraphQL::Types::String,
          required: true,
          description: 'Description of the AI flow trigger.'

        argument :event_types, [GraphQL::Types::Int],
          required: false,
          description: 'Event types that triggers the AI flow.'

        argument :filter, GraphQL::Types::JSON, # rubocop:disable Graphql/JSONType -- filter schema is not model backend
          required: false,
          experiment: { milestone: '19.0' },
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

        argument :config_path, GraphQL::Types::String,
          required: false,
          description: 'Path to the configuration file for the AI flow trigger.'

        argument :ai_catalog_item_consumer_id, ::Types::GlobalIDType[::Ai::Catalog::ItemConsumer],
          prepare: ->(global_id, _ctx) { global_id&.model_id&.to_i },
          required: false,
          description: 'AI catalog item consumer to use instead of config_path.'

        argument :active, GraphQL::Types::Boolean,
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Indicates whether the AI flow trigger is active. Defaults to true.'

        field :ai_flow_trigger,
          Types::Ai::FlowTriggerType,
          description: 'Created AI flow trigger.'

        field :error_reason,
          Types::Ai::FlowTrigger::ErrorReasonEnum,
          null: true,
          experiment: { milestone: '19.6' },
          description: 'Machine-readable reason for the mutation error.'

        def resolve(project_path:, **params)
          project = authorized_find!(project_path)

          if config_validation_rate_limited?
            return { ai_flow_trigger: nil, errors: [config_validation_rate_limited_message] }
          end

          response = ::Ai::FlowTriggers::CreateService.new(project: project,
            current_user: context[:current_user]).execute(params)

          service_response_payload(response)
        end
      end
    end
  end
end
