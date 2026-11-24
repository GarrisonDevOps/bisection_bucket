# frozen_string_literal: true

module Sbom
  class DeleteExpiredExportsWorker
    include ApplicationWorker
    # rubocop:disable Scalability/CronWorkerContext -- This job does not require context
    include CronjobQueue

    # rubocop:enable Scalability/CronWorkerContext

    idempotent!

    worker_resource_boundary :cpu
    data_consistency :sticky
    feature_category :dependency_management

    def perform
      Dependencies::DependencyListExport.expired.each_batch do |batch|
        destroy_export_parts_for(batch)

        batch.tap { |exports| Upload.destroy_for_associations!(exports) }
             .delete_all
      end
    end

    private

    # The parts cascade away with their export, which drops the rows without
    # their uploads and leaves orphans that fail Geo verification.
    def destroy_export_parts_for(batch)
      Dependencies::DependencyListExport::Part.for_exports(batch).each_batch do |parts|
        parts.tap { |records| Upload.destroy_for_associations!(records) }
             .delete_all
      end
    end
  end
end
