# frozen_string_literal: true

module Vulnerabilities
  module ConsistencyChecks
    class Orchestrator
      CONSISTENCY_CHECKS = [
        HasVulnerabilitiesIsCorrectCheck,
        BackfillIssueLinkOccurrenceIdCheck,
        BackfillMergeRequestLinkOccurrenceIdCheck,
        TriggerParityCheck,
        TrackedContextTraversalIdsCheck,
        DuplicateDefaultTrackedContextsCheck
      ].freeze

      def initialize(project)
        @project = project
      end

      attr_reader :project

      def execute
        synchronous_checks.each { |check| check.enqueue(project) }

        # The async sweep checks are the expensive whole-project ones; throttle
        # them to at most once per cooldown per project. Synchronous checks above
        # run every time, outside the throttle. The cooldown is set before the
        # async checks are enqueued, so a raise in an enqueue, or a later failed
        # sweep, still uses up the cooldown until it expires.
        Gitlab::Utils::RedisThrottle.execute_every(
          ConsistencyChecks::COOLDOWN_PERIOD,
          ConsistencyChecks.cooldown_key(project)
        ) do
          asynchronous_checks.each { |check| check.enqueue(project) }
        end
      end

      private

      def synchronous_checks
        CONSISTENCY_CHECKS.select(&:synchronous?)
      end

      def asynchronous_checks
        CONSISTENCY_CHECKS.reject(&:synchronous?)
      end
    end
  end
end
