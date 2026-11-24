# frozen_string_literal: true

module Types
  module SecurityOrchestration
    # rubocop: disable Graphql/AuthorizeTypes -- authorization
    # this represents a hash, from the orchestration policy configuration
    # the authorization happens for that configuration
    class PipelineExecutionSchedulePolicyType < PipelineExecutionScheduledPolicyAttributesType
      graphql_name 'PipelineExecutionSchedulePolicy'
      description 'Represents the pipeline execution schedule policy'

      # Skip granular PAT authorization at this level. Authorization is handled by child types
      # (e.g., PipelineExecutionProjectScheduleType) which perform boundary-based checks.
      authorize_granular_token skip_reason: :child_authorizes

      implements OrchestrationPolicyType

      field :schedule_pipelines, Types::Security::PolicySchedulePipelineType.connection_type,
        null: true,
        resolver: Resolvers::Security::PolicySchedulePipelinesResolver,
        description: 'Pipelines created by this scheduled policy.',
        experiment: { milestone: '19.0' }

      field :upcoming_schedules, Types::Security::PipelineExecutionProjectScheduleType.connection_type,
        null: true,
        resolver: Resolvers::Security::UpcomingPolicySchedulesResolver,
        description: 'Upcoming scheduled runs for this policy.',
        experiment: { milestone: '19.1' }
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
