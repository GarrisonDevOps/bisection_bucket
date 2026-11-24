# frozen_string_literal: true

module Gitlab
  module Ci
    class RunnersAvailabilityChecker
      include ::Gitlab::Utils::StrongMemoize

      Result = Struct.new(:available?, :drop_reason)

      def self.instance_for(project)
        key = "runner_availability_checker:#{project.id}"

        ::Gitlab::SafeRequestStore.fetch(key) do
          new(project)
        end
      end

      def check(build_matcher)
        all_checks.each do |runner_check, drop_reason|
          return Result.new(false, drop_reason) unless runner_check.available?(build_matcher)
        end

        Result.new(true, nil)
      end

      private

      attr_reader :project, :runner_matchers

      def initialize(project) # rubocop:disable Layout/ClassStructure -- method is private
        @project = project
        @runner_matchers = project.all_runners.active.online.runner_matchers
      end

      def all_checks
        {
          Gitlab::Ci::RunnersAvailability::Minutes
            .new(project, runner_matchers) => :ci_quota_exceeded,
          Gitlab::Ci::RunnersAvailability::AllowedPlans
            .new(project, runner_matchers) => :no_matching_runner
        }
      end
      strong_memoize_attr :all_checks
    end
  end
end
