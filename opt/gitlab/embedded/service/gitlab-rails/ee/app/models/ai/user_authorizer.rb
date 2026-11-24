# frozen_string_literal: true

module Ai
  # Answers Duo access questions for one user. Replaces the methods that
  # Ai::UserAuthorizable adds to User; see
  # https://gitlab.com/gitlab-org/gitlab/-/work_items/636699
  class UserAuthorizer
    include Gitlab::Utils::StrongMemoize

    # refers to add-ons listed in GitlabSubscriptions::SystemDefined::AddOn::DUO_ADD_ONS
    DUO_ADD_ONS_CACHE_KEY = 'user-%{user_id}-duo-add-ons-cache'
    DUO_PRO_ADD_ON_CACHE_KEY = 'user-%{user_id}-code-suggestions-add-on-cache'
    GROUP_WITH_AI_ENABLED_CACHE_KEY = 'group_with_ai_enabled'
    GROUP_WITH_AI_ENABLED_CACHE_PERIOD = 1.hour
    GROUP_WITH_MCP_SERVER_ENABLED_CACHE_KEY = 'group_with_mcp_server_enabled'
    GROUP_WITH_MCP_SERVER_ENABLED_CACHE_PERIOD = 1.hour
    ROOT_GROUP_IDS_CACHE_KEY = 'root_group_ids'
    ROOT_GROUP_IDS_CACHE_PERIOD = 10.minutes

    def self.clear_group_with_ai_available_cache(ids)
      cache_keys_ai_features = Array.wrap(ids).map { |id| ["users", id, GROUP_WITH_AI_ENABLED_CACHE_KEY] }
      cache_keys_billable_duo_pro_group_ids = Array.wrap(ids).map do |id|
        ["users", id, ROOT_GROUP_IDS_CACHE_KEY]
      end

      cache_keys = cache_keys_ai_features + cache_keys_billable_duo_pro_group_ids
      ::Gitlab::Instrumentation::RedisClusterValidator.allow_cross_slot_commands do
        Rails.cache.delete_multi(cache_keys)
      end
    end

    def self.clear_group_with_mcp_server_enabled_cache(ids)
      cache_keys = Array.wrap(ids).map do |id|
        ["users", id, GROUP_WITH_MCP_SERVER_ENABLED_CACHE_KEY]
      end

      ::Gitlab::Instrumentation::RedisClusterValidator.allow_cross_slot_commands do
        Rails.cache.delete_multi(cache_keys)
      end
    end

    def self.duo_pro_cache_key_formatted(user_id)
      format(DUO_PRO_ADD_ON_CACHE_KEY, user_id: user_id)
    end

    # One authorizer per user per request, so memoized lookups are shared by every caller.
    def self.for(user)
      return new(user) unless user&.id

      Gitlab::SafeRequestStore.fetch([:ai_user_authorizer, user.id]) { new(user) }
    end

    def initialize(user)
      @user = user
    end

    def any_group_with_mcp_server_enabled?
      Rails.cache.fetch(
        ['users', user.id, GROUP_WITH_MCP_SERVER_ENABLED_CACHE_KEY],
        expires_in: GROUP_WITH_MCP_SERVER_ENABLED_CACHE_PERIOD
      ) do
        ::Group.by_id(gitlab_com_root_group_ids).with_mcp_server_enabled.any?
      end
    end

    def eligible_for_self_managed_gitlab_duo_pro?
      return false if user.gitlab_com_subscription?

      user.active? && !user.bot? && !user.ghost?
    end

    # rubocop: disable Database/AvoidUsingPluckWithoutLimit -- limited to a single user's groups
    def gitlab_com_root_group_ids
      return unless user.gitlab_com_subscription?

      Rails.cache.fetch(
        ['users', user.id, ROOT_GROUP_IDS_CACHE_KEY],
        expires_in: ROOT_GROUP_IDS_CACHE_PERIOD
      ) do
        banned_root_group_ids = ::Namespaces::NamespaceBan.where(user_id: user.id).pluck(:namespace_id)

        user.authorized_root_ancestor_ids - banned_root_group_ids
      end
    end
    # rubocop: enable Database/AvoidUsingPluckWithoutLimit -- limited to a single user's groups

    def groups_with_duo_core_enabled
      ::Namespace.id_in(gitlab_com_root_group_ids).namespace_settings_with_duo_core_features_enabled
    end

    def gitlab_credits_purchases
      @gitlab_credits_purchases ||= if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
                                      GitlabSubscriptions::AddOnPurchase
                                        .for_gitlab_credits.for_user(user).active
                                        .includes(namespace: :ai_settings).to_a
                                    else
                                      GitlabSubscriptions::AddOnPurchase
                                        .for_gitlab_credits.for_self_managed.active.to_a
                                    end
    end

    def governing_namespace(scope = nil)
      root_namespace = scope&.root_ancestor || root_namespace_from_application_context

      if root_namespace && !root_namespace.user_namespace? && authorized_root_namespace?(root_namespace)
        return root_namespace
      end

      default_duo_namespace
    end

    alias_method :billable_duo_namespace, :governing_namespace

    def default_duo_namespace
      user.user_preference.duo_default_namespace_with_fallback
    end

    def duo_available_namespace_ids
      Rails.cache.fetch(duo_addons_cache_key_formatted, expires_in: 1.hour) do
        GitlabSubscriptions::UserAddOnAssignment.by_user(user).for_active_gitlab_duo_purchase
          .pluck('subscription_add_on_purchases.namespace_id') # rubocop: disable Database/AvoidUsingPluckWithoutLimit -- limited to a single user's purchases
          .uniq
      end
    end

    # Duo Core granted at the namespace level, without a per-user add-on assignment.
    def duo_core_ids_via_namespace_settings
      groups = groups_with_duo_core_enabled
      groups.present? ? groups.ids : []
    end

    private

    attr_reader :user

    def authorized_root_namespace?(root_namespace)
      strong_memoize_with(:authorized_root_namespace, root_namespace.id) do
        next false if user.banned_from_namespace?(root_namespace)
        next true if root_namespace.member_of_self_or_descendant?(user)

        indirect_member_under?(root_namespace) && duo_access_through?(root_namespace)
      end
    end

    # The seat list is cached for an hour. The Duo Core and credits lists run queries, so check them last.
    def duo_access_through?(root_namespace)
      duo_available_namespace_ids.include?(root_namespace.id) ||
        duo_core_access_through?(root_namespace) ||
        gitlab_credits_purchases.any? { |purchase| purchase.namespace_id == root_namespace.id }
    end

    def duo_addons_cache_key_formatted
      format(DUO_ADD_ONS_CACHE_KEY, user_id: user.id)
    end

    def duo_core_access_through?(root_namespace)
      duo_core_ids_via_namespace_settings.include?(root_namespace.id) &&
        GitlabSubscriptions::AddOnPurchase.for_duo_core.active.by_namespace(root_namespace).exists?
    end

    # Built from project authorizations and cached for 10 minutes. It is nil off GitLab.com.
    def indirect_member_under?(root_namespace)
      !!gitlab_com_root_group_ids&.include?(root_namespace.id)
    end

    def root_namespace_from_application_context
      group_path = Gitlab::ApplicationContext.current_context_attribute(:group)
      project_path = Gitlab::ApplicationContext.current_context_attribute(:project)

      if group_path
        ::Group.find_by_full_path(group_path)&.root_ancestor
      elsif project_path
        ::Project.find_by_full_path(project_path)&.root_ancestor
      end
    end
  end
end
