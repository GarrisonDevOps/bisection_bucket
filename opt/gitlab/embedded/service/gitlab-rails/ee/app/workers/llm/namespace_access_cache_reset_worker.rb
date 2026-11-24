# frozen_string_literal: true

module Llm
  class NamespaceAccessCacheResetWorker
    include Gitlab::EventStore::Subscriber

    data_consistency :delayed
    feature_category :ai_abstraction_layer
    urgency :low
    deduplicate :until_executed, if_deduplicated: :reschedule_once
    idempotent!
    concurrency_limit -> { 10 }

    defer_on_database_health_signal :gitlab_main, %i[members], 10.minutes

    def handle_event(event)
      if batched_hierarchy_reset?(event)
        reset_hierarchy_in_batches(event.data[:group_id])
        return
      end

      members = members_for_event(event)
      return if members.blank?

      ::Ai::UserAuthorizer.clear_group_with_ai_available_cache(members.pluck_user_ids)
    end

    private

    def batched_hierarchy_reset?(event)
      event.is_a?(::NamespaceSettings::AiRelatedSettingsChangedEvent) &&
        Feature.enabled?(:batch_ai_namespace_access_cache_reset, Group.actor_from_id(event.data[:group_id]))
    end

    def reset_hierarchy_in_batches(group_id)
      group = Group.find_by_id(group_id)
      return unless group && group.licensed_feature_available?(:ai_features)

      user_id_batches = 0
      user_ids_cleared = 0

      ::Ai::HierarchyMemberUserIds.new(group).each_user_ids_batch do |user_ids|
        ::Ai::UserAuthorizer.clear_group_with_ai_available_cache(user_ids)
        user_id_batches += 1
        user_ids_cleared += user_ids.size
      end

      log_hash_metadata_on_done(user_id_batches: user_id_batches, user_ids_cleared: user_ids_cleared)
    end

    def members_for_event(event)
      case event
      when ::NamespaceSettings::AiRelatedSettingsChangedEvent
        group = Group.find_by_id(event.data[:group_id])
        return unless group && group.licensed_feature_available?(:ai_features)

        all_members_unique_by_user(group)
      when ::Members::AddedCloudEvent
        payload = event.event_data
        source = payload[:source_type].constantize.find_by_id(payload[:source_id])
        return unless source && source.licensed_feature_available?(:ai_features)

        source.members.created_after(::Ai::UserAuthorizer::GROUP_WITH_AI_ENABLED_CACHE_PERIOD.ago)
      end
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
