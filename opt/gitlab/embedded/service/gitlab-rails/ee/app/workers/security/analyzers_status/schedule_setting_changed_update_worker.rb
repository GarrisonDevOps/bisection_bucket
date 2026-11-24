# frozen_string_literal: true

module Security
  module AnalyzersStatus
    class ScheduleSettingChangedUpdateWorker
      include ApplicationWorker

      idempotent!
      data_consistency :sticky
      feature_category :security_asset_inventories

      BATCH_SIZE = 100
      DELAY = 30.seconds.to_i

      def perform(project_ids, analyzer_type)
        return unless project_ids.present? && analyzer_type.present?

        project_ids.each_slice(BATCH_SIZE).each_with_index do |projects_slice, index|
          SettingChangedUpdateWorker.perform_in(DELAY * index, projects_slice, analyzer_type)
        end
      end
    end
  end
end
