# frozen_string_literal: true

module Types
  module Security
    class PolicySchedulePipelineType < BaseObject
      graphql_name 'PolicySchedulePipeline'
      description 'Represents a pipeline created by a scheduled security policy.'

      authorize :read_policy_schedule_pipeline

      field :id, ::Types::GlobalIDType[::Security::PolicySchedulePipeline],
        null: false,
        description: 'ID of the policy schedule pipeline record.'

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp when the pipeline was triggered by the schedule.'

      field :pipeline, Types::Ci::PipelineType,
        null: false,
        description: 'Pipeline created by the scheduled policy.'

      field :project, Types::ProjectType,
        null: false,
        description: 'Project the pipeline was created for.'
    end
  end
end
