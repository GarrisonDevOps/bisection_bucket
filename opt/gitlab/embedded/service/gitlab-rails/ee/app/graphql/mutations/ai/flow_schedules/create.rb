# frozen_string_literal: true

module Mutations
  module Ai
    module FlowSchedules
      class Create < BaseMutation
        graphql_name 'AiFlowScheduleCreate'

        authorize :create_ai_flow_schedule
        authorize_granular_token permissions: :create_ai_flow_schedule,
          boundary_argument: :flow_trigger_id, boundary: :project, boundary_type: :project

        argument :flow_trigger_id, ::Types::GlobalIDType[::Ai::FlowTrigger],
          required: true,
          description: 'Global ID of the flow trigger to schedule.'

        argument :description, GraphQL::Types::String,
          required: true,
          description: 'Description of the schedule.'

        argument :cron, GraphQL::Types::String,
          required: true,
          description: 'Cron expression defining the schedule frequency.'

        argument :cron_timezone, GraphQL::Types::String,
          required: true,
          description: 'IANA timezone for the cron expression.'

        argument :active, GraphQL::Types::Boolean,
          required: false,
          default_value: true,
          description: 'Indicates whether the schedule should be active.'

        field :ai_flow_schedule,
          Types::Ai::FlowScheduleType,
          null: true,
          description: 'Created flow schedule.'

        def resolve(flow_trigger_id:, **params)
          flow_trigger = authorized_find!(id: flow_trigger_id)

          response = ::Ai::FlowSchedules::CreateService.new(
            flow_trigger: flow_trigger,
            current_user: current_user
          ).execute(params)

          {
            ai_flow_schedule: response.success? ? response.payload[:flow_schedule] : nil,
            errors: response.success? ? [] : [response.message]
          }
        end

        private

        def find_object(id:)
          GitlabSchema.find_by_gid(id)
        end
      end
    end
  end
end
