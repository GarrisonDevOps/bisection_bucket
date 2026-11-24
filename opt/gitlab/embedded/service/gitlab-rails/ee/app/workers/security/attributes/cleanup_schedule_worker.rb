# frozen_string_literal: true

module Security
  module Attributes
    class CleanupScheduleWorker
      include Gitlab::EventStore::Subscriber

      idempotent!
      data_consistency :sticky
      feature_category :security_asset_inventories

      PROJECTS_BATCH_SIZE = 500
      BATCH_DELAY = 2.seconds

      def handle_event(event)
        moved_group = Group.find_by_id(event.data[:group_id])
        old_root_namespace_id = event.data[:old_root_namespace_id]
        return unless moved_group && old_root_namespace_id
        return unless Security::Attribute.by_namespace(old_root_namespace_id).exists?

        new_root_namespace_id = moved_group.root_ancestor.id
        new_root_namespace_id = nil if old_root_namespace_id == new_root_namespace_id

        schedule_update_batches(moved_group, new_root_namespace_id)
      end

      private

      def schedule_update_batches(moved_group, new_root_namespace_id)
        project_ids = Gitlab::Database::NamespaceProjectIdsEachBatch.new(
          group_id: moved_group.id
        ).execute

        return if project_ids.empty?

        project_ids.each_slice(PROJECTS_BATCH_SIZE).with_index do |project_ids_batch, index|
          Security::Attributes::CleanupBatchWorker.perform_in(
            index * BATCH_DELAY,
            project_ids_batch,
            new_root_namespace_id
          )
        end
      end
    end
  end
end
