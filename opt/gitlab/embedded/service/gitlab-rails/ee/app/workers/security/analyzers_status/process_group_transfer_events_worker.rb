# frozen_string_literal: true

module Security
  module AnalyzersStatus
    class ProcessGroupTransferEventsWorker
      include Gitlab::EventStore::Subscriber
      include Gitlab::ExclusiveLeaseHelpers

      data_consistency :sticky
      idempotent!
      deduplicate :until_executing, including_scheduled: true

      feature_category :security_asset_inventories
      defer_on_database_health_signal :gitlab_sec, [:analyzer_namespace_statuses], 1.minute

      LEASE_TTL = 5.minutes
      LEASE_TRY_AFTER = 2.seconds
      LEASE_RETRIES = 2
      RETRY_IN_IF_LOCKED = 20.seconds
      PROJECTS_BATCH_SIZE = 500
      BATCH_DELAY = 2.seconds

      def handle_event(event)
        group = Group.find_by_id(event.data[:group_id])

        return unless group

        # Inventory filter rows can exist without status rows, so only the status steps are gated.
        if group.analyzer_group_statuses.exists?
          in_lock(lease_key(group.id), ttl: LEASE_TTL, sleep_sec: LEASE_TRY_AFTER, retries: LEASE_RETRIES) do
            UpdateGroupAncestorsStatusesService.execute(group)
            UpdateNamespaceTraversalIdsService.execute(group)
          end
        end

        schedule_inventory_filters_update(group)

      rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
        self.class.handle_event_in(RETRY_IN_IF_LOCKED, event)
      end

      def lease_key(group_id)
        "security:#{group_id}:process_group_transfer_events_worker"
      end

      private

      def schedule_inventory_filters_update(group)
        project_ids = Gitlab::Database::NamespaceProjectIdsEachBatch.new(group_id: group.id).execute

        project_ids.each_slice(PROJECTS_BATCH_SIZE).with_index do |batch, index|
          Security::InventoryFilters::UpdateTraversalIdsWorker.perform_in(index * BATCH_DELAY, batch)
        end
      end
    end
  end
end
