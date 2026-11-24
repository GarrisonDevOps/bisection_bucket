# frozen_string_literal: true

module Mcp
  class NamespaceAccessCacheResetWorker
    include Gitlab::EventStore::Subscriber

    data_consistency :delayed
    feature_category :mcp_server
    urgency :low
    deduplicate :until_executed, if_deduplicated: :reschedule_once
    idempotent!
    concurrency_limit -> { 10 }

    defer_on_database_health_signal :gitlab_main, %i[members], 10.minutes

    def handle_event(event)
      group = Group.find_by_id(event.data[:group_id])
      return unless group

      if Feature.enabled?(:batch_ai_namespace_access_cache_reset, group)
        reset_hierarchy_in_batches(group)
        return
      end

      user_ids = all_members_unique_by_user(group).pluck_user_ids
      return if user_ids.blank?

      ::Ai::UserAuthorizer.clear_group_with_mcp_server_enabled_cache(user_ids)
    end

    private

    def reset_hierarchy_in_batches(group)
      user_id_batches = 0
      user_ids_cleared = 0

      ::Ai::HierarchyMemberUserIds.new(group).each_user_ids_batch do |user_ids|
        ::Ai::UserAuthorizer.clear_group_with_mcp_server_enabled_cache(user_ids)
        user_id_batches += 1
        user_ids_cleared += user_ids.size
      end

      log_hash_metadata_on_done(user_id_batches: user_id_batches, user_ids_cleared: user_ids_cleared)
    end

    def all_members_unique_by_user(group)
      Member.from_union(
        [
          group.descendant_project_members_with_inactive.select(:user_id),
          group.members_with_descendants.select(:user_id)
        ],
        remove_duplicates: true
      ).select(:user_id)
    end
  end
end
