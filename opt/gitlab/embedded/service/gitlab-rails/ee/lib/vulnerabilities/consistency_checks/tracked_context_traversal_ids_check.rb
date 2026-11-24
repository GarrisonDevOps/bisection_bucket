# frozen_string_literal: true

module Vulnerabilities
  module ConsistencyChecks
    class TrackedContextTraversalIdsCheck < BaseCheck
      DRIFT_LOG_MESSAGE = 'Detected drifted tracked context traversal_ids, scheduling a resync'

      def execute
        return unless sync_enabled?

        super
      end

      def consistent?
        project.security_project_tracked_contexts
          .with_traversal_ids_other_than(project.namespace.traversal_ids)
          .none?
      end

      def fix!
        log(DRIFT_LOG_MESSAGE)

        ::Security::SyncTrackedContextTraversalIdsWorker.perform_async(project.id)
      end

      def execute_async
        return unless sync_enabled?

        super
      end

      private

      def sync_enabled?
        Feature.enabled?(:sync_drifted_tracked_context_traversal_ids, project)
      end
    end
  end
end
