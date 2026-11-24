# frozen_string_literal: true

module EE
  module Ci
    module BuildFinishedWorker
      def process_build(build, pipeline)
        # Always run `super` first since it contains sync operations.
        # Failing to run sync operations would cause the worker to retry
        # and enqueueing duplicate jobs.
        super

        if requirements_available?(build) && !test_report_already_generated?(build)
          RequirementsManagement::ProcessRequirementsReportsWorker.perform_async(build.id)
        end

        if ::Gitlab.com? && build.has_security_reports?
          ::Security::TrackSecureScansWorker.perform_async(build.id)
        end

        ::Ci::InstanceRunnerFailedJobs.track(build) if build.failed?

        # Use upsert since this code can be called more than once for the same build
        ::Ci::FinishedBuildChSyncEvent.upsert_from_build(build) if finished_build_sync_event?(build)
      end

      private

      def test_report_already_generated?(build)
        RequirementsManagement::TestReport.for_user_build(build.user_id, build.id).exists?
      end

      def requirements_available?(build)
        build.project.feature_available?(:requirements, build.user) &&
          !build.project.requirements.empty? &&
          Ability.allowed?(build.user, :create_requirement_test_report, build.project)
      end

      def finished_build_sync_event?(build)
        build.is_a?(::Ci::Build) && build.finished_at.present?
      end
    end
  end
end
