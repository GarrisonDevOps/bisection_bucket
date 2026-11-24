# frozen_string_literal: true

module Analytics
  module Orbit
    module MemberNotifications
      class TodoWorker
        include ApplicationWorker

        data_consistency :delayed
        feature_category :knowledge_graph
        urgency :low
        deduplicate :until_executed
        idempotent!
        defer_on_database_health_signal :gitlab_main_org,
          [:knowledge_graph_enabled_namespaces, :todos], 10.minutes

        concurrency_limit -> { 10 }

        NAMESPACE_BATCH_SIZE = 100
        USER_BATCH_SIZE = 1_000

        def perform(root_namespace_id)
          group = ::Group.find_by_id(root_namespace_id)
          return unless group
          return unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
          return unless group.knowledge_graph_enabled_namespace

          todo_service = ::TodoService.new

          group.self_and_descendants.each_batch(of: NAMESPACE_BATCH_SIZE) do |namespaces|
            eligible_user_ids(namespaces.pluck_primary_key).each_slice(USER_BATCH_SIZE) do |user_ids|
              users = ::User.active.without_bots.id_in(user_ids).to_a
              todo_service.orbit_access_granted(users) if users.any?
            end
          end
        end

        private

        def eligible_user_ids(namespace_ids)
          ::GroupMember
            .active_without_invites_and_requests
            .with_source_id(namespace_ids)
            .with_at_least_access_level(::Gitlab::Access::REPORTER)
            .pluck_user_ids
            .uniq
        end
      end
    end
  end
end
