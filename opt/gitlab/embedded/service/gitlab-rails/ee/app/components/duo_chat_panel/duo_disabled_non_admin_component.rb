# frozen_string_literal: true

module DuoChatPanel
  class DuoDisabledNonAdminComponent < ViewComponent::Base
    def initialize(container:, user:)
      @container = container
      @user = user
    end

    private

    attr_reader :container, :user

    def data
      {
        testid: 'duo-chat-panel-duo-disabled-non-admin',
        is_duo_disabled_non_admin: 'true',
        # Force agentic_available to true so the router uses the agentic chat component,
        # which has the isDuoDisabledNonAdmin empty state UI
        agentic_available: 'true',
        auto_expand: 'false',
        container_type: container.type,
        namespace_id: container.namespace_id,
        project_id: container.project_id
      }.compact
    end
  end
end
