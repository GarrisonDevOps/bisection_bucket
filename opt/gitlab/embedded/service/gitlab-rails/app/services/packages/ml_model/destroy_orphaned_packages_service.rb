# frozen_string_literal: true

module Packages
  module MlModel
    # Packages that still have files are destroyed by Packages::CleanupPackageFileWorker after their last file.
    class DestroyOrphanedPackagesService
      BATCH_SIZE = 25
      TIME_LIMIT = 1.second

      def initialize(package_ids)
        @package_ids = package_ids
      end

      def execute
        deadline = TIME_LIMIT.from_now

        package_ids.each_slice(BATCH_SIZE) do |ids|
          destroy_batch(ids)

          break if deadline.past?
        end
      rescue ActiveRecord::ActiveRecordError => e
        # Callers run this after their own delete committed, so a failure here must not fail them.
        # The later batches are skipped on purpose: the rows stay pending_destruction and the work is bounded.
        Gitlab::ErrorTracking.track_exception(e)
      end

      private

      attr_reader :package_ids

      # The row lock blocks new package files, which take FOR KEY SHARE on the package. The delete then checks
      # the scope again on a new snapshot, so a file committed before the lock keeps its package. The scope
      # excludes packages with files, and the database cascades the other associations.
      def destroy_batch(ids)
        ::Packages::Package.transaction do
          locked_ids = ::Packages::MlModel::Package.lock_orphaned_ids(ids, BATCH_SIZE)
          ::Packages::MlModel::Package.id_in(locked_ids).orphaned.delete_all if locked_ids.any?
        end
      end
    end
  end
end
