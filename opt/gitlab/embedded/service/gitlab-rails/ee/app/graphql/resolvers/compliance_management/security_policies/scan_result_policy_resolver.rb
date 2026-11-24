# frozen_string_literal: true

module Resolvers
  module ComplianceManagement
    module SecurityPolicies
      class ScanResultPolicyResolver < BaseResolver
        type Types::SecurityOrchestration::ScanResultPolicyType, null: true
        calls_gitaly!

        def resolve
          ::Gitlab::Graphql::Aggregations::SecurityOrchestrationPolicies::LazyComplianceFrameworkAggregate.new(
            context, object, :scan_result_policies
          )
        end
      end
    end
  end
end
