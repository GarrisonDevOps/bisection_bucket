# frozen_string_literal: true

module Security
  module AnalyzersStatus
    class ProcessGroupArchivedEventsWorker
      include Gitlab::EventStore::Subscriber

      idempotent!
      deduplicate :until_executing, including_scheduled: true
      data_consistency :sticky
      feature_category :security_asset_inventories

      BATCH_SIZE = 100
      BASE_DELAY_MINUTES = 5
      DELAY_EXPONENT = 0.7
      DELAY_DIVISOR = 7
      MAX_DELAY_HOURS = 6

      def handle_event(event)
        return unless event.data[:group_id]

        namespace_id = event.data[:group_id]
        project_count = 0

        cursor = { current_id: namespace_id, depth: [namespace_id] }
        iterator = Gitlab::Database::NamespaceEachBatch.new(namespace_class: Group, cursor: cursor)

        iterator.each_batch(of: BATCH_SIZE) do |ids, _new_cursor|
          Project.in_namespace(ids).each_batch(of: BATCH_SIZE) do |project_batch|
            bulk_schedule_project_statuses_worker(project_batch)
            project_count += project_batch.size
          end
        end

        delay = calculate_recalculation_delay(project_count)
        AnalyzerNamespaceStatuses::RecalculateWorker.perform_in(
          delay, namespace_id, AnalyzerNamespaceStatuses::RecalculateWorker::GROUP_ARCHIVED_TRIGGER
        )
      end

      private

      def bulk_schedule_project_statuses_worker(projects)
        UpdateArchivedAnalyzerStatusWorker.perform_async(projects.map(&:id))
      end

      def calculate_recalculation_delay(project_count)
        # Examples:
        #   100 projects: ~7 minutes
        #   1,000 projects: ~22 minutes
        #   10,000 projects: ~137 minutes (~2.3 hours)

        base_delay = BASE_DELAY_MINUTES.minutes
        delay = base_delay + ((project_count**DELAY_EXPONENT) / DELAY_DIVISOR).minutes

        [delay, MAX_DELAY_HOURS.hours].min
      end
    end
  end
end
