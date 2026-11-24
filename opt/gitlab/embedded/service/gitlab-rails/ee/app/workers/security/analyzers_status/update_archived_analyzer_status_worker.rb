# frozen_string_literal: true

module Security
  module AnalyzersStatus
    class UpdateArchivedAnalyzerStatusWorker
      include ApplicationWorker

      idempotent!
      data_consistency :sticky
      feature_category :security_asset_inventories
      concurrency_limit -> { 25 }
      defer_on_database_health_signal :gitlab_sec, [:analyzer_project_statuses], 1.minute
      sidekiq_retry_in { 2.minutes.seconds.to_i }
      deduplicate :until_executing, including_scheduled: true

      BATCH_SIZE = 100

      def perform(project_ids)
        project_ids = Array(project_ids) # For backwards compatibility with a single project_id

        project_ids.each_slice(BATCH_SIZE) do |ids|
          projects = Project.id_in(ids).to_a
          ActiveRecord::Associations::Preloader.new(
            records: projects,
            associations: [:project_namespace, { namespace: :namespace_settings_with_ancestors_inherited_settings }]
          ).call

          UpdateArchivedService.execute(projects)
        end
      end
    end
  end
end
