# frozen_string_literal: true

module Types
  module Security
    class PipelineExecutionProjectScheduleType < BaseObject
      graphql_name 'PipelineExecutionProjectSchedule'
      description 'Represents a project schedule for a pipeline execution policy.'

      authorize :read_pipeline_execution_project_schedule
      authorize_granular_token permissions: :read_pipeline_execution_project_schedule,
        boundary: :policy_management_project,
        boundary_type: :project

      field :id, ::Types::GlobalIDType[::Security::PipelineExecutionProjectSchedule],
        null: false,
        description: 'ID of the schedule record.'

      field :project, Types::ProjectType,
        null: false,
        description: 'Project the scheduled pipeline will run for.'

      field :next_run_at, Types::TimeType,
        null: true,
        description: 'Timestamp of the next scheduled run.'

      field :cron, GraphQL::Types::String,
        null: false,
        description: 'Cron expression for the schedule.'

      field :cron_timezone, GraphQL::Types::String,
        null: false,
        description: 'Timezone for the cron schedule.'

      field :time_window_seconds, GraphQL::Types::Int,
        null: false,
        description: 'Time window in seconds for distributing pipeline runs.'

      field :snoozed_until, Types::TimeType,
        null: true,
        description: 'Timestamp until which the schedule is snoozed.'

      def next_run_at
        return unless object.next_run_at

        object.next_run_at.in_time_zone(object.cron_timezone)
      end
    end
  end
end
