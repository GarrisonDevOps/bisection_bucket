# frozen_string_literal: true

module Gitlab
  module Export
    class SegmentedExportWorker
      include ApplicationWorker

      feature_category :vulnerability_management
      data_consistency :delayed
      deduplicate :until_executing
      idempotent!

      def perform(global_id, segment_ids)
        export_record = GlobalID.find(global_id)

        ::Gitlab::SegmentedExport::SegmentExporterService.new(export_record, segment_ids).execute
      end
    end
  end
end
