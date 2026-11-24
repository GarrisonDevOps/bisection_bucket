# frozen_string_literal: true

module DuoChatPanel
  class ChatComponent < ViewComponent::Base
    include SafeFormatHelper
    include DuoChatPanel::PanelCommon
    include DuoChatPanel::PanelAutoExpand
    include ::Gitlab::Utils::StrongMemoize

    VALID_DUO_ADD_ONS = %w[duo_enterprise duo_pro duo_core].freeze

    def initialize(container:, user:)
      @container = container
      @user = user
    end

    private

    attr_reader :container, :user

    def data
      { testid: 'duo-chat-panel-chat' }
        .merge(scope_data)
        .merge(duo_chat_data)
        .merge(chat_feature_data)
        .merge(subscription_status_data)
        .merge(billing_attributes)
        .merge(free_addon_data)
        .merge(hand_raise_lead_data)
    end

    def hand_raise_lead_data
      return {} unless can_buy? && free_addon_credits_namespace?

      helpers.hand_raise_modal_dataset(governing_namespace).transform_keys { |key| :"hand_raise_lead_#{key}" }
    end

    def scope_data
      {
        user_id: user.to_global_id,
        project_id: container.project_id,
        project_path: container.project_path,
        namespace_id: container.namespace_id,
        root_namespace_id: container.root_namespace_id,
        default_namespace_governs: default_namespace_governs?.to_s,
        resource_id: ::Gitlab::ApplicationContext.current_context_attribute(:ai_resource).presence,
        metadata: duo_workflow_metadata
      }
    end

    def duo_workflow_metadata
      ::Gitlab::DuoWorkflow::Client.metadata(
        user,
        namespace: container.root_ancestor,
        project: container.project
      ).to_json
    end

    def duo_chat_data
      is_agentic_available = duo_chat.agentic_mode_available?

      {
        user_model_selection_enabled: duo_chat.user_model_selection_enabled?.to_s,
        agentic_available: is_agentic_available.to_s,
        classic_available: duo_chat.classic_chat_available?.to_s,
        chat_disabled_reason: duo_chat.chat_disabled_reason.to_s,
        credits_available: credits_available_for_panel.to_s,
        default_namespace_selected: duo_chat.default_duo_namespace_check_passes?.to_s,
        agentic_unavailable_message: agentic_unavailable_message(is_agentic_available),
        duo_agent_platform_enabled: duo_agent_platform_enabled?.to_s,
        web_search_allowed_for_group: web_search_allowed_for_group?.to_s,
        file_attachments_allowed: ::Ai::FileAttachments.allowed?(container.root_ancestor, user: user).to_s
      }
    end

    def duo_agent_platform_enabled?
      ::Ai::DuoWorkflow.duo_agent_platform_available?(container.record)
    end

    def web_search_allowed_for_group?
      ::Ai::DuoWorkflow.web_search_allowed?(container.record)
    end

    # Skip the credits check (which hits the customers portal) when the
    # subscription is expired - the panel will render the cancelled empty state
    # and credit availability is irrelevant.
    def credits_available_for_panel
      return false if subscription_expired?(container.record)

      duo_chat.credits_available?
    end

    def chat_feature_data
      # Without a dev server origin the panel loads the copy bundled from @gitlab-mfe/duo-chat.
      mfe_server_origin = ENV['MFE_SERVER_ORIGIN'].presence if Rails.env.development?

      {
        force_agentic_mode_for_core_duo_users: force_agentic_mode_for_core_duo_users?.to_s,
        chat_title: chat_title,
        duo_settings_path: duo_disabled_admin_settings_path,
        preferences_path: ::Gitlab::Routing.url_helpers.profile_preferences_path(anchor: 'duo'),
        explore_ai_catalog_path: (::Gitlab::Routing.url_helpers.explore_ai_catalog_path if ai_catalog_available?),
        auto_expand: should_auto_expand_panel?(user, 'duo_panel_auto_expanded').to_s,
        mfe_local_mode: mfe_server_origin.nil?.to_s,
        mfe_server_origin: mfe_server_origin
      }
    end

    def ai_catalog_available?
      Ability.allowed?(user, :read_ai_catalog)
    end

    def duo_chat
      @duo_chat ||= ::Gitlab::Llm::DuoChat.new(user: user, container: container.record)
    end

    def subscription_status_data
      if saas?
        saas_subscription_status
      else
        self_managed_subscription_status
      end
    end

    def saas_subscription_status
      namespace = container.root_ancestor
      return { trial_active: nil, subscription_active: nil, subscription_expired: 'false' } unless namespace

      {
        trial_active: namespace.trial_active?.to_s,
        subscription_active: GitlabSubscriptions.active?(namespace).to_s,
        subscription_expired: saas_subscription_expired?(container.record).to_s
      }
    end

    def self_managed_subscription_status
      return { trial_active: nil, subscription_active: nil, subscription_expired: 'false' } unless License.current

      {
        trial_active: License.current.trial?.to_s,
        subscription_active: License.current.paid?.to_s,
        subscription_expired: self_managed_subscription_expired?.to_s
      }
    end

    def billing_attributes
      {
        is_saas: saas?.to_s,
        is_trial: trial?.to_s,
        can_buy_addon: can_buy?.to_s,
        buy_addon_path: buy_addon_path,
        purchase_credits_path: purchase_credits_path,
        tier_upgrade_path: tier_upgrade_path
      }
    end

    def governing_namespace
      user.governing_namespace(container.record)
    end
    strong_memoize_attr :governing_namespace

    # On GitLab.com, the page's top-level group decides agent availability only when the user
    # has GitLab Duo access there. Otherwise the default GitLab Duo namespace decides.
    def default_namespace_governs?
      return false unless saas?

      container.default_namespace_applied? || governing_namespace != container.root_ancestor
    end

    def can_buy?
      if saas?
        governing_namespace.present? && Ability.allowed?(user, :edit_billing, governing_namespace)
      else
        Ability.allowed?(user, :admin_all_resources)
      end
    end
    strong_memoize_attr :can_buy?

    def trial?
      if saas?
        !!governing_namespace&.trial_active?
      else
        !!License.current&.trial?
      end
    end
    strong_memoize_attr :trial?

    def buy_addon_path
      return unless can_buy?
      return ::Gitlab::Routing.url_helpers.subscription_portal_url if trial?

      if saas?
        ::Gitlab::Routing.url_helpers.group_settings_gitlab_credits_dashboard_index_path(governing_namespace)
      else
        ::Gitlab::Routing.url_helpers.admin_gitlab_credits_dashboard_index_path
      end
    end

    def purchase_credits_path
      return unless can_buy?

      if saas?
        purchase_credits_path_for_saas
      else
        purchase_credits_path_for_self_managed
      end
    end

    def tier_upgrade_path
      return unless saas? && governing_namespace

      ::Gitlab::Routing.url_helpers.upgrade_base_plan_subscriptions_path(namespace_id: governing_namespace.id)
    end

    def purchase_credits_path_for_self_managed
      ::Gitlab::Routing.url_helpers.subscription_portal_self_managed_purchase_credits_url(
        subscription_name: License.current&.subscription_name
      )
    end

    def purchase_credits_path_for_saas
      ::Gitlab::Routing.url_helpers.subscription_portal_gitlab_com_purchase_credits_url(governing_namespace.id)
    end

    # rubocop:disable Layout/LineLength -- i18n
    def agentic_unavailable_message(is_agentic_available)
      return if is_agentic_available

      response = user.allowed_to_use(
        :agentic_chat,
        unit_primitive_name: :duo_chat,
        root_namespace: container.root_ancestor
      )

      return unless response.allowed? && container.record.nil? && VALID_DUO_ADD_ONS.include?(response.enablement_type)

      preferences_url = ::Gitlab::Routing.url_helpers.profile_preferences_path(anchor: 'duo')
      preferences_link = helpers.link_to('', preferences_url)
      safe_format(
        s_('DuoChat|GitLab Duo Agentic Chat is not available on this page. To use GitLab Duo Agentic Chat outside a project, select a %{strong_start}default group for GitLab Duo%{strong_end} in your %{preferences_link_start}preferences%{preferences_link_end}.'),
        tag_pair(helpers.content_tag(:strong, ''), :strong_start, :strong_end).merge(
          tag_pair(preferences_link, :preferences_link_start, :preferences_link_end)
        )
      )
    end
    # rubocop:enable Layout/LineLength

    def free_addon_data
      { is_free_addon_credits_user: free_addon_credits_user?.to_s }
    end

    def free_addon_credits_user?
      duo_chat_authorization_response.allowed? &&
        duo_chat_authorization_response.enablement_type == "gitlab_credits"
    end

    def free_addon_credits_namespace?
      saas? && governing_namespace.present? && governing_namespace.free_plan_with_gitlab_credits_add_on?
    end

    def force_agentic_mode_for_core_duo_users?
      return false unless ::Feature.enabled?(:no_duo_classic_for_duo_core_users, user)

      duo_chat_authorization_response.allowed? &&
        duo_chat_authorization_response.enablement_type == "duo_core"
    end

    def duo_chat_authorization_response
      user.allowed_to_use(:agentic_chat, unit_primitive_name: :duo_chat)
    end
    strong_memoize_attr :duo_chat_authorization_response

    def chat_title
      ::Ai::AmazonQ.enabled? ? _('GitLab Duo Chat with Amazon Q') : _('GitLab Duo Chat')
    end

    def duo_disabled_admin_settings_path
      return unless container.record && !container.default_namespace_applied?

      response = ::Gitlab::Llm::Chain::Utils::ChatAuthorizer.container(container: container.record, user: user)
      return if response.allowed?

      duo_settings_path_for
    end

    # TODO: Consolidate with Container#admin_duo_settings_path, which applies the same persistence,
    # scope and permission checks https://gitlab.com/gitlab-org/gitlab/-/work_items/596322
    def duo_settings_path_for
      return unless container.user_can_admin?(user)

      container.duo_settings_path
    end
  end
end
