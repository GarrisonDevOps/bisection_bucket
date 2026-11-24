# frozen_string_literal: true

module GitlabSubscriptions
  module MemberManagement
    class MinimalAccessProvisioningNotificationService
      include ::GitlabSubscriptions::MemberManagement::SeatAwareProvisioning

      def self.execute
        new.execute
      end

      def initialize
        @sync_date = Date.yesterday.iso8601
        @previous_sync_date = (Date.yesterday - 1.day).iso8601
      end

      def execute
        IdempotencyCache.ensure_idempotency(notifications_enqueued_cache_key, 25.hours) do
          if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
            notify_saas_namespaces
          else
            notify_self_managed_instance
          end
        end
      end

      private

      attr_reader :sync_date, :previous_sync_date

      def notify_saas_namespaces
        root_group_ids = cached_items(format_root_groups_cache_key(sync_date))
        return if root_group_ids.empty?

        currently_affected, previously_affected = fetch_affected_users_for_groups(root_group_ids)

        qualifying_group_ids = qualifying_groups(root_group_ids, currently_affected, previously_affected)
        return if qualifying_group_ids.empty?

        Group.by_id(qualifying_group_ids).each_batch(of: 100) do |batch|
          batch.preload_owners.each do |group|
            affected_users = currently_affected[group.id.to_s]

            group.owners.each do |owner|
              GitlabSubscriptions::MemberManagement::MinimalAccessProvisioningMailer.notify_group_owner(
                namespace: group,
                recipient: owner,
                user_count: affected_users.count,
                sync_date: sync_date).deliver_later
            end
          end
        end
      end

      def notify_self_managed_instance
        affected_users = cached_items(format_instance_cache_key(sync_date))
        return if affected_users.empty?

        previously_affected_users = cached_items(format_instance_cache_key(previous_sync_date))
        return unless newly_affected_users?(affected_users, previously_affected_users)

        User.admins.active.find_each do |admin|
          GitlabSubscriptions::MemberManagement::MinimalAccessProvisioningMailer.notify_instance_admin(
            recipient: admin,
            user_count: affected_users.count,
            sync_date: sync_date).deliver_later
        end
      end

      # We'll suppress the notification if there are no newly affected users since yesterday,
      # because a notification was already sent on the previous day. Resending would create
      # duplicate alerts for the same users affected by the Minimal Access fallback
      def newly_affected_users?(affected_users, previously_affected_users)
        (affected_users - previously_affected_users).any?
      end

      def cached_items(cache_key)
        ::Gitlab::Redis::SharedState.with do |redis|
          redis.smembers(cache_key)
        end
      end

      def fetch_affected_users_for_groups(group_ids)
        current_results, previous_results = ::Gitlab::Redis::SharedState.with do |redis|
          [
            redis.pipelined { |p| group_ids.each { |id| p.smembers(format_users_cache_key(id, sync_date)) } },
            redis.pipelined { |p| group_ids.each { |id| p.smembers(format_users_cache_key(id, previous_sync_date)) } }
          ]
        end

        [group_ids.zip(current_results).to_h, group_ids.zip(previous_results).to_h]
      end

      def notifications_enqueued_cache_key
        "seat_aware_provisioning:notifications_enqueued:{#{sync_date}}"
      end

      def qualifying_groups(group_ids, currently_affected, previously_affected)
        group_ids.select do |group_id|
          affected_users = currently_affected[group_id]
          next false if affected_users.empty?

          previously_affected_users = previously_affected[group_id]

          newly_affected_users?(affected_users, previously_affected_users)
        end
      end
    end
  end
end
