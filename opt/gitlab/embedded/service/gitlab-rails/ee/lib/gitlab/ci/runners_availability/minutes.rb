# frozen_string_literal: true

module Gitlab
  module Ci
    module RunnersAvailability
      class Minutes < Base
        def available?(build_matcher)
          return true unless project.shared_runners_enabled?

          !quota_exceeded?(build_matcher)
        end

        private

        def quota_exceeded?(build_matcher)
          matches_instance_runners_and_quota_used_up?(build_matcher) &&
            !matches_private_runners?(build_matcher)
        end

        def matches_instance_runners_and_quota_used_up?(build_matcher)
          instance_runners.any? do |matcher|
            matcher.matches?(build_matcher) &&
              !matcher.matches_quota?(build_matcher)
          end
        end
      end
    end
  end
end
