# frozen_string_literal: true

module EE
  module Ci
    module PendingBuild
      extend ActiveSupport::Concern

      prepended do
        scope :with_ci_minutes_available, -> { where(minutes_exceeded: false) }
        scope :with_allowed_plan_name_uids, ->(uids) { where(plan_name_uid: uids) }
      end

      class_methods do
        extend ::Gitlab::Utils::Override

        override :args_from_build
        def args_from_build(build)
          fields = { minutes_exceeded: minutes_exceeded?(build.project) }

          if ::Gitlab::Saas.feature_available?(:ci_runners_allowed_plans)
            plan = build.project.actual_plan
            fields[:plan_name_uid] = plan.plan_name_uid_before_type_cast
          end

          super.merge(fields)
        end

        private

        def minutes_exceeded?(project)
          ::Ci::Runner.any_shared_runners_with_enabled_cost_factor?(project) &&
            project.ci_minutes_usage.minutes_used_up?
        end
      end
    end
  end
end
