# frozen_string_literal: true

module Security
  module ScanProfiles
    class ProcessGroupTransferEventsWorker
      include Gitlab::EventStore::Subscriber

      idempotent!
      data_consistency :sticky
      feature_category :security_testing_configuration

      # A same-root move walks the whole hierarchy to resync traversal_ids, which is
      # coarse-grained work compared to the per-batch jobs it enqueues.
      concurrency_limit -> { 10 }

      BATCH_SIZE = 100
      BATCH_DELAY = 2.seconds

      def handle_event(event)
        group_id = event.data[:group_id]
        old_root_namespace_id = event.data[:old_root_namespace_id]
        new_root_namespace_id = event.data[:new_root_namespace_id]

        group = Group.find_by_id(group_id)
        return unless group

        # Across roots the associations are removed anyway, so only a move that keeps
        # them needs their denormalized traversal_ids brought up to date.
        if old_root_namespace_id == new_root_namespace_id
          schedule_traversal_ids_sync(group, new_root_namespace_id)
        elsif was_nested_group?(group_id, old_root_namespace_id) # Different root namespace - Only delete connections
          schedule_project_connections_cleanup(group_id, old_root_namespace_id)
        elsif became_nested_group?(group_id, new_root_namespace_id) # Was root and became nested - Delete profiles
          schedule_profiles_cleanup(group)
        end
      end

      private

      def schedule_traversal_ids_sync(group, root_namespace_id)
        return unless Security::ScanProfile.not_deleted.by_namespace(root_namespace_id).exists?

        attached_project_ids(group).each_slice(BATCH_SIZE).with_index do |batch, index|
          Security::ScanProfiles::UpdateTraversalIdsWorker.perform_in(index * BATCH_DELAY, batch)
        end
      end

      # Narrowed to attached projects to keep the array small. `pluck_primary_key` is
      # required: the query runs on `gitlab_sec` and cannot take a `projects` subquery.
      def attached_project_ids(group)
        Gitlab::Database::NamespaceProjectIdsEachBatch.new(
          group_id: group.id,
          resolver: ->(batch) { Security::ScanProfileProject.attached_project_ids(batch.pluck_primary_key) },
          batch_size: BATCH_SIZE
        ).execute
      end

      def was_nested_group?(group_id, old_root_namespace_id)
        old_root_namespace_id != group_id
      end

      def became_nested_group?(group_id, new_root_namespace_id)
        new_root_namespace_id != group_id
      end

      def schedule_project_connections_cleanup(group_id, old_root_namespace_id)
        return unless Security::ScanProfile.by_namespace(old_root_namespace_id).exists?

        Security::ScanProfiles::CleanOldNamespaceConnectionsWorker.perform_async(group_id, true)
      end

      def schedule_profiles_cleanup(group)
        profiles_ids = group.security_scan_profiles.scan_profile_ids
        return unless profiles_ids.any?

        Security::ScanProfiles::DeleteScanProfilesWorker.perform_async(profiles_ids, group.id)
      end
    end
  end
end
