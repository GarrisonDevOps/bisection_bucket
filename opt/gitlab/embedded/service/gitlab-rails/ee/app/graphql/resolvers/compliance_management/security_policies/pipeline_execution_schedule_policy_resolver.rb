# frozen_string_literal: true

module Resolvers
  module ComplianceManagement
    module SecurityPolicies
      class PipelineExecutionSchedulePolicyResolver < BaseResolver
        include ResolvesOrchestrationPolicy

        type Types::SecurityOrchestration::PipelineExecutionSchedulePolicyType, null: true

        def resolve
          ::Gitlab::Graphql::Aggregations::SecurityOrchestrationPolicies::LazyComplianceFrameworkAggregate.new(
            context, object, :pipeline_execution_schedule_policies
          )
        end
      end
    end
  end
end
