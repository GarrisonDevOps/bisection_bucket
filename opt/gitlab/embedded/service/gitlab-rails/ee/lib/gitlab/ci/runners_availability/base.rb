# frozen_string_literal: true

module Gitlab
  module Ci
    module RunnersAvailability
      class Base
        include ::Gitlab::Utils::StrongMemoize

        def initialize(project, runner_matchers)
          @project = project
          @runner_matchers = runner_matchers
        end

        private

        attr_reader :project, :runner_matchers

        def matches_private_runners?(build_matcher)
          private_runners.any? { |matcher| matcher.matches?(build_matcher) }
        end

        def instance_runners
          runner_matchers.select(&:instance_type?)
        end
        strong_memoize_attr :instance_runners

        def private_runners
          runner_matchers.reject(&:instance_type?)
        end
        strong_memoize_attr :private_runners
      end
    end
  end
end
