# frozen_string_literal: true

module WorkItems
  module Statuses
    class BackfillProjectRowsWorker
      include ApplicationWorker

      MAX_RUNTIME = 3.minutes
      RETRY_DELAY = 2.minutes

      data_consistency :sticky
      feature_category :team_planning
      urgency :low
      idempotent!
      deduplicate :until_executed, if_deduplicated: :reschedule_once
      concurrency_limit -> { 10 }
      defer_on_database_health_signal :gitlab_main_org, [:work_item_current_statuses], 1.minute
      sidekiq_options max_retries_after_interruption: 20

      def perform(project_id, iid = nil)
        project = Project.find_by_id(project_id)
        return unless project

        root_namespace = project.root_ancestor
        return unless root_namespace.custom_lifecycles.exists?

        namespace_id = project.project_namespace_id
        resume_at = { namespace_id: namespace_id, iid: iid } if iid
        limiter = Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)

        result = BackfillConvertedStatusIdsService.new(root_namespace)
          .execute([namespace_id], limiter, resume_at: resume_at).payload

        self.class.perform_in(RETRY_DELAY, project_id, result[:resume_at][:iid]) unless result[:completed]

        log_extra_metadata_on_done(:result, result)
      end
    end
  end
end
