# frozen_string_literal: true

module Types
  module SecurityOrchestration
    # rubocop: disable Graphql/AuthorizeTypes -- Authorization handled in the resolver
    # this represents a hash, from the orchestration policy configuration
    # the authorization happens for that configuration
    class PipelineExecutionScheduledPolicyAttributesType < PipelineExecutionPolicyAttributesType
      graphql_name 'PipelineExecutionScheduledPolicyAttributesType'
      description 'Represents policy fields related to the pipeline execution scheduled policy.'

      field :schedule_time_window_seconds, GraphQL::Types::Int,
        null: true,
        experiment: { milestone: '19.1' },
        description: 'Time window in seconds from the first schedule of the policy.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
