# frozen_string_literal: true

module Gitlab
  module Ci
    module RunnersAvailability
      class AllowedPlans < Base
        def available?(build_matcher)
          return true unless project.shared_runners_enabled?

          !plan_not_matched?(build_matcher)
        end

        private

        def plan_not_matched?(build_matcher)
          matches_instance_runners_but_not_plans?(build_matcher) &&
            !matches_private_runners?(build_matcher)
        end

        def matches_instance_runners_but_not_plans?(build_matcher)
          instance_runners.any? do |matcher|
            matcher.matches?(build_matcher) &&
              !matcher.matches_allowed_plans?(build_matcher)
          end
        end
      end
    end
  end
end
