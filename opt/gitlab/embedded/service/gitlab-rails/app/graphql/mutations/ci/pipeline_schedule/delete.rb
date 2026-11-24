# frozen_string_literal: true

module Mutations
  module Ci
    module PipelineSchedule
      class Delete < Base
        graphql_name 'PipelineScheduleDelete'

        authorize :admin_pipeline_schedule
        authorize_granular_token permissions: :delete_pipeline_schedule, boundary_argument: :id, boundary: :project,
          boundary_type: :project

        def resolve(id:)
          schedule = authorized_find!(id: id)

          response = ::Ci::PipelineSchedules::DestroyService.new(schedule, current_user).execute

          { errors: response.errors }
        end
      end
    end
  end
end
