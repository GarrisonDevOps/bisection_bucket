# frozen_string_literal: true

module Resolvers
  module ComplianceManagement
    module SecurityPolicies
      class AllPoliciesResolver < BaseResolver
        type ::Types::ComplianceManagement::ComplianceFrameworkPolicySummaryType, null: true

        calls_gitaly!

        def resolve
          ::Gitlab::Graphql::Aggregations::SecurityOrchestrationPolicies::LazyComplianceFrameworkAllPoliciesAggregate.new(
            context, object
          )
        end
      end
    end
  end
end
