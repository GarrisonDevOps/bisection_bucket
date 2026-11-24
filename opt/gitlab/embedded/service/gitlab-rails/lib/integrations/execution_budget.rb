# frozen_string_literal: true

module Integrations
  # Per top-level namespace, per minute budget for enqueueing
  # Integrations::ExecuteWorker jobs. The budget bucket comes from
  # Integration#execution_budget_key and the threshold from PlanLimits.
  # A limit of 0 means unlimited.
  class ExecutionBudget
    include Gitlab::Utils::StrongMemoize

    NO_LIMIT = 0

    def initialize(integration)
      @integration = integration
    end

    # Increments the counter. Returns true if the integration is over budget.
    def throttled?
      return false if budget_key.nil? || root_namespace.nil? || limit == NO_LIMIT

      ::Gitlab::ApplicationRateLimiter.throttled?(
        budget_key,
        scope: { namespace: root_namespace },
        threshold: limit
      )
    end

    def budget_key
      @integration.execution_budget_key
    end

    def root_namespace
      resolved.first
    end

    def limit
      resolved.last
    end

    private

    # One event fans out to every integration of a project or group, so the
    # root namespace and plan limit are resolved once per parent and bucket.
    def resolved
      parent = @integration.project || @integration.group
      return [nil, NO_LIMIT] if parent.nil? || budget_key.nil?

      ::Gitlab::SafeRequestStore.fetch(request_store_key(parent)) do
        root = parent.root_ancestor
        [root, root.actual_limits.limit_for(budget_key) || NO_LIMIT]
      end
    end
    strong_memoize_attr :resolved

    def request_store_key(parent)
      "integration_execution_budget:#{parent.class.name}:#{parent.id}:#{budget_key}"
    end
  end
end
