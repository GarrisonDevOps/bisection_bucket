# frozen_string_literal: true

module Mutations
  module Ai
    module FlowSchedules
      class Update < BaseMutation
        graphql_name 'AiFlowScheduleUpdate'

        authorize :update_ai_flow_schedule
        authorize_granular_token permissions: :update_ai_flow_schedule,
          boundary_argument: :id, boundary: :project, boundary_type: :project

        argument :id, ::Types::GlobalIDType[::Ai::FlowSchedule],
          required: true,
          description: 'Global ID of the flow schedule to update.'

        argument :description, GraphQL::Types::String,
          required: false,
          description: 'Description of the schedule.'

        argument :cron, GraphQL::Types::String,
          required: false,
          description: 'Cron expression defining the schedule frequency.'

        argument :cron_timezone, GraphQL::Types::String,
          required: false,
          description: 'IANA timezone for the cron expression.'

        argument :active, GraphQL::Types::Boolean,
          required: false,
          description: 'Indicates whether the schedule should be active.'

        field :ai_flow_schedule,
          Types::Ai::FlowScheduleType,
          null: true,
          description: 'Updated flow schedule.'

        def resolve(id:, **params)
          flow_schedule = authorized_find!(id: id)

          response = ::Ai::FlowSchedules::UpdateService.new(
            flow_schedule: flow_schedule,
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
