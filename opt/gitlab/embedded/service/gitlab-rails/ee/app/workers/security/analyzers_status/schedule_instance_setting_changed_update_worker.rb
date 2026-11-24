# frozen_string_literal: true

module Security
  module AnalyzersStatus
    class ScheduleInstanceSettingChangedUpdateWorker
      include ApplicationWorker

      idempotent!
      data_consistency :sticky
      feature_category :security_asset_inventories

      BATCH_SIZE = 1000
      DELAY_INTERVAL = 30.seconds.to_i

      def perform(analyzer_type)
        return unless analyzer_type.present?

        Project.each_batch(of: BATCH_SIZE) do |batch, index|
          project_ids = batch.pluck_primary_key
          ScheduleSettingChangedUpdateWorker.perform_in(index * DELAY_INTERVAL, project_ids, analyzer_type)
        end
      end
    end
  end
end
