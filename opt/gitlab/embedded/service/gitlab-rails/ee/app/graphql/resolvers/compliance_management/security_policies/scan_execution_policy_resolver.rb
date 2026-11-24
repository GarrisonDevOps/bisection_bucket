# frozen_string_literal: true

module Resolvers
  module ComplianceManagement
    module SecurityPolicies
      class ScanExecutionPolicyResolver < BaseResolver
        include ResolvesOrchestrationPolicy

        type Types::SecurityOrchestration::ScanExecutionPolicyType, null: true

        def resolve
          ::Gitlab::Graphql::Aggregations::SecurityOrchestrationPolicies::LazyComplianceFrameworkAggregate.new(
            context, object, :scan_execution_policies
          )
        end
      end
    end
  end
end
