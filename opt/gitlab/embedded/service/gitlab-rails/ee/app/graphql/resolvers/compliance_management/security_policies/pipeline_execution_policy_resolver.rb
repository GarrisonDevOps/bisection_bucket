# frozen_string_literal: true

module Resolvers
  module ComplianceManagement
    module SecurityPolicies
      class PipelineExecutionPolicyResolver < BaseResolver
        include ResolvesOrchestrationPolicy

        type Types::SecurityOrchestration::PipelineExecutionPolicyType, null: true

        def resolve
          ::Gitlab::Graphql::Aggregations::SecurityOrchestrationPolicies::LazyComplianceFrameworkAggregate.new(
            context, object, :pipeline_execution_policies
          )
        end
      end
    end
  end
end
