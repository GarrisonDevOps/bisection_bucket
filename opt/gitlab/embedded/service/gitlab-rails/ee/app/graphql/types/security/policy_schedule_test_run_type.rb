# frozen_string_literal: true

module Types
  module Security
    class PolicyScheduleTestRunType < BaseObject
      graphql_name 'PolicyScheduleTestRun'
      description 'Represents a test run for a scheduled pipeline execution policy.'

      authorize :read_policy_schedule_test_run

      field :id, ::Types::GlobalIDType[::Security::ScheduledPipelineExecutionPolicyTestRun],
        null: false,
        description: 'ID of the test run.'

      field :state, PolicyScheduleTestRunStateEnum,
        null: false,
        description: 'State of the test run.'

      field :started_at, Types::TimeType,
        null: true,
        description: 'Timestamp when the test run started.'

      field :finished_at, Types::TimeType,
        null: true,
        description: 'Timestamp when the test run finished.'

      field :duration, GraphQL::Types::Int,
        null: true,
        description: 'Duration of the test run in seconds.'

      field :error_message, GraphQL::Types::String,
        null: true,
        description: 'Error message if the test run failed.'

      field :project, Types::ProjectType,
        null: false,
        description: 'Project the test run was executed on.'

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp when the test run was created.'

      field :pipeline, Types::Ci::PipelineType,
        null: true,
        description: 'Pipeline created by the test run.'

      field :completed, GraphQL::Types::Boolean,
        null: false,
        method: :completed?,
        description: 'Whether the test run has completed.'
    end
  end
end
