# frozen_string_literal: true

module DuoChatPanel
  class DuoDisabledAdminComponent < ViewComponent::Base
    include DuoChatPanel::PanelAutoExpand

    def initialize(container:, user:)
      @container = container
      @user = user
    end

    private

    attr_reader :container, :user

    def data
      {
        testid: 'duo-chat-panel-duo-disabled-admin',
        # The panel keys the "Turn on GitLab Duo" empty state off chat_disabled_reason
        # combined with duo_settings_path.
        chat_disabled_reason: container.type,
        duo_settings_path: container.admin_duo_settings_path(user),
        # The blocked state is routed by shouldShowBlockedState, not by this attribute. It is set
        # for parity with the other blocked states, which the panel's router treats as agentic.
        agentic_available: 'true',
        auto_expand: should_auto_expand_panel?(user, 'duo_panel_auto_expanded').to_s,
        container_type: container.type,
        namespace_id: container.namespace_id,
        project_id: container.project_id
      }.compact
    end
  end
end
