# frozen_string_literal: true

module Security
  module AnalyzerNamespaceStatuses
    class ScheduleWorker
      include ApplicationWorker
      include Security::NamespaceTraversalSqlBuilder

      idempotent!
      data_consistency :sticky

      # rubocop:disable Scalability/CronWorkerContext -- This worker doesn't have a scoped context.
      include CronjobQueue

      # rubocop:enable Scalability/CronWorkerContext

      feature_category :security_asset_inventories

      BATCH_SIZE = 500
      DELAY_INTERVAL = 30.seconds.to_i

      # Only processes namespaces with matching analyzer statuses instead of all group namespaces
      def perform
        pending_ids = []
        index = 0

        Namespace.group_namespaces.each_batch(of: BATCH_SIZE) do |relation|
          namespace_values = pluck_namespace_ids_and_traversal_ids(relation.not_deletion_in_progress, limit: BATCH_SIZE)

          namespace_ids = FindNamespacesWithAnalyzerStatusesService.execute(namespace_values)
          next unless namespace_ids.present?

          pending_ids.concat(namespace_ids)
          next unless pending_ids.length >= BATCH_SIZE

          schedule_batch_processing(index, pending_ids.shift(BATCH_SIZE))
          index += 1
        end

        schedule_batch_processing(index, pending_ids) unless pending_ids.empty?
      end

      private

      def schedule_batch_processing(index, batch_ids)
        AnalyzerNamespaceStatuses::AdjustmentWorker.perform_in(index * DELAY_INTERVAL, batch_ids)
      end
    end
  end
end
