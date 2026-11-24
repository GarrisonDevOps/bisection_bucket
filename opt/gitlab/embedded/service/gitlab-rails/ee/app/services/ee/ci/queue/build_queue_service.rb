# frozen_string_literal: true

module EE
  module Ci
    module Queue
      module BuildQueueService
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        override :builds_for_shared_runner
        def builds_for_shared_runner
          # if disaster recovery is enabled, we disable quota
          builds = if ::Feature.enabled?(:ci_queueing_disaster_recovery_disable_quota, runner, type: :ops)
                     super
                   else
                     enforce_minutes_based_on_cost_factors(super)
                   end

          if ::Feature.enabled?(:ci_queuing_disaster_recovery_disable_allowed_plans, :instance, type: :ops)
            builds
          else
            enforce_allowed_plans(builds)
          end
        end

        def enforce_minutes_based_on_cost_factors(relation)
          strategy.enforce_minutes_limit(relation)
        end

        def enforce_allowed_plans(relation)
          return relation if runner.allowed_plan_name_uids.empty?

          strategy.enforce_allowed_plan_name_uids(relation, runner.allowed_plan_name_uids)
        end
      end
    end
  end
end
