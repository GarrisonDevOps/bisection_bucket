# frozen_string_literal: true

module Resolvers
  module SecurityOrchestration
    class PipelineExecutionPolicyResolver < BaseResolver
      include ResolvesOrchestrationPolicy
      include ConstructPipelineExecutionPolicies

      type Types::SecurityOrchestration::PipelineExecutionPolicyType, null: true

      argument :relationship, ::Types::SecurityOrchestration::SecurityPolicyRelationTypeEnum,
        description: 'Filter policies by the given policy relationship. Default is DIRECT.',
        required: false,
        default_value: :direct

      argument :include_unscoped, GraphQL::Types::Boolean,
        description: 'Filter policies that are scoped to the project.',
        required: false,
        default_value: true

      argument :deduplicate_policies, GraphQL::Types::Boolean,
        description: 'Remove duplicate policies when the same policy is applied via multiple routes.',
        required: false,
        default_value: false

      def resolve(**args)
        policies = ::Security::PipelineExecutionPoliciesFinder.new(context[:current_user], project, args).execute
        construct_pipeline_execution_policies(policies)
      end
    end
  end
end
