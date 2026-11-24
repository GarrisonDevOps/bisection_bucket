# frozen_string_literal: true

module Types
  module Ci
    class JobMinimalAccessType < BaseObject
      graphql_name 'CiJobMinimalAccess'

      authorize :read_build_metadata

      implements ::Types::Ci::JobInterface

      field :active, GraphQL::Types::Boolean, null: false, method: :active?,
        description: 'Indicates the job is active.'
      field :allow_failure, ::GraphQL::Types::Boolean, null: false,
        description: 'Whether the job is allowed to fail.'
      field :coverage, GraphQL::Types::Float, null: true,
        description: 'Coverage level of the job.'
      field :created_by_tag, GraphQL::Types::Boolean, null: false,
        description: 'Whether the job was created by a tag.', method: :tag?
      field :detailed_status, Types::Ci::DetailedStatusType, null: true,
        description: 'Detailed status of the job.'
      field :duration, GraphQL::Types::Int, null: true,
        description: 'Duration of the job in seconds.'
      field :finished_at, Types::TimeType, null: true,
        description: 'When a job has finished running.'
      field :id, ::Types::GlobalIDType[::CommitStatus].as('JobID'), null: true,
        description: 'ID of the job.'
      field :manual_job, GraphQL::Types::Boolean, null: true,
        description: 'Whether the job has a manual action.'
      field :name, GraphQL::Types::String, null: true,
        description: 'Name of the job.'
      field :pipeline, Types::Ci::PipelineInterface, null: true,
        description: 'Pipeline the job belongs to.'
      field :project, Types::Projects::ProjectInterface, null: true, description: 'Project that the job belongs to.'
      field :queued_duration,
        type: Types::DurationType,
        null: true,
        description: 'How long the job was enqueued before starting.'
      field :ref_name, GraphQL::Types::String, null: true,
        description: 'Ref name of the job.'
      field :runner, Types::Ci::RunnerType, null: true, description: 'Runner assigned to execute the job.'
      field :scheduled_at, Types::TimeType, null: true,
        description: 'Schedule for the build.'
      field :short_sha, type: GraphQL::Types::String, null: false,
        description: 'Short SHA1 ID of the commit.'
      field :status,
        type: ::Types::Ci::JobStatusEnum,
        null: true,
        description: "Status of the job."
      field :stuck, GraphQL::Types::Boolean, null: false, method: :stuck?,
        description: 'Indicates the job is stuck.'
      field :tags, [GraphQL::Types::String], null: true,
        description: 'Tags for the current job.'
      field :triggered, GraphQL::Types::Boolean, null: true,
        description: 'Whether the job was triggered.'

      def tags
        object.tag_list if object.is_a?(::Ci::Build)
      end
    end
  end
end
