# frozen_string_literal: true

module Mutations
  module Ai
    module FlowSchedules
      class Delete < BaseMutation
        graphql_name 'AiFlowScheduleDelete'

        authorize :delete_ai_flow_schedule
        authorize_granular_token permissions: :delete_ai_flow_schedule,
          boundary_argument: :id, boundary: :project, boundary_type: :project

        argument :id, ::Types::GlobalIDType[::Ai::FlowSchedule],
          required: true,
          description: 'Global ID of the flow schedule to delete.'

        field :ai_flow_schedule,
          Types::Ai::FlowScheduleType,
          null: true,
          description: 'Deleted flow schedule.'

        def resolve(id:)
          flow_schedule = authorized_find!(id: id)

          response = ::Ai::FlowSchedules::DestroyService.new(
            flow_schedule: flow_schedule,
            current_user: current_user
          ).execute

          {
            ai_flow_schedule: response.success? ? flow_schedule : nil,
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
