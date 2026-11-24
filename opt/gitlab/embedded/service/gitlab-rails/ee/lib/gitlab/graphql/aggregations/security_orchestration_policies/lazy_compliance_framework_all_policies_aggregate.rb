# frozen_string_literal: true

module Gitlab
  module Graphql
    module Aggregations
      module SecurityOrchestrationPolicies
        class LazyComplianceFrameworkAllPoliciesAggregate < LazyComplianceFrameworkAggregate
          def initialize(query_ctx, object)
            super(query_ctx, object, nil)
          end

          private

          def result
            @lazy_state[:loaded_objects][@object.id]&.values&.flatten || []
          end
        end
      end
    end
  end
end
