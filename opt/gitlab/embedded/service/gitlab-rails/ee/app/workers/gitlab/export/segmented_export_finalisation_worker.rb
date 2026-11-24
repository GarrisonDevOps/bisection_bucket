# frozen_string_literal: true

module Gitlab
  module Export
    class SegmentedExportFinalisationWorker
      include ApplicationWorker

      feature_category :vulnerability_management
      data_consistency :delayed
      deduplicate :until_executed
      idempotent!

      def perform(global_id)
        export = GlobalID.find(global_id)

        ::Gitlab::SegmentedExport::FinalizerService.new(export).execute
      end
    end
  end
end
