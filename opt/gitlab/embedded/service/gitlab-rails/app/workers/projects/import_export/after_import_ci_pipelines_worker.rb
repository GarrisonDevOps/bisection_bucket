# frozen_string_literal: true

module Projects
  module ImportExport
    class AfterImportCiPipelinesWorker
      include ApplicationWorker

      MAX_RUNTIME = 3.minutes
      RETRY_DELAY = 1.minute

      idempotent!
      data_consistency :delayed
      urgency :low
      feature_category :importers
      deduplicate :until_executed, if_deduplicated: :reschedule_once
      defer_on_database_health_signal :gitlab_main_org, [:merge_requests], 1.minute
      sidekiq_options max_retries_after_interruption: 20

      def perform(project_id, cursor = nil)
        project = Project.find_by_id(project_id)
        return unless project

        limiter = Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)
        result = LinkMergeRequestHeadPipelinesService.new(project).execute(limiter, cursor: cursor)

        self.class.perform_in(RETRY_DELAY, project_id, result.payload[:cursor]) unless result.payload[:completed]
      end
    end
  end
end
