# frozen_string_literal: true

module Gitlab
  module BackgroundMigration
    # Deletes pending_destruction ml_model packages with no file and no model version: the package
    # file cleanup worker only reaches packages with files. See Packages::MlModel::DestroyOrphanedPackagesService.
    class DeleteOrphanedMlModelPackages < BatchedMigrationJob
      ML_MODEL_PACKAGE_TYPE = 14
      PENDING_DESTRUCTION_STATUS = 4

      cursor :id
      operation_name :delete_orphaned_ml_model_packages
      feature_category :mlops

      def perform
        each_sub_batch do |sub_batch|
          connection.transaction do
            locked_ids = orphaned(sub_batch.klass.where(id: sub_batch.select(:id)))
              .lock('FOR UPDATE SKIP LOCKED')
              .pluck(:id)

            orphaned(sub_batch.klass.where(id: locked_ids)).delete_all if locked_ids.any?
          end
        end
      end

      private

      def orphaned(relation)
        relation
          .where(package_type: ML_MODEL_PACKAGE_TYPE, status: PENDING_DESTRUCTION_STATUS)
          .where('NOT EXISTS (SELECT 1 FROM packages_package_files WHERE package_id = packages_packages.id)')
          .where('NOT EXISTS (SELECT 1 FROM ml_model_versions WHERE package_id = packages_packages.id)')
      end
    end
  end
end
