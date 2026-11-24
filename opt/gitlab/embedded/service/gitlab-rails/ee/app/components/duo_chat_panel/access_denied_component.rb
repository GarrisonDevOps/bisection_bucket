# frozen_string_literal: true

module DuoChatPanel
  class AccessDeniedComponent < ViewComponent::Base
    include ::Gitlab::Utils::StrongMemoize

    def initialize(container:, user:)
      @container = container
      @user = user
    end

    private

    attr_reader :container, :user

    def data
      {
        testid: 'duo-chat-panel-access-denied',
        access_denied: true.to_s,
        container_type: container.type,
        auto_expand: 'false'
      }.merge(request_duo_data).compact
    end

    def request_duo_data
      return {} unless eligibility.eligible?

      {
        request_duo_group_id: eligibility.root.id,
        request_duo_requested: eligibility.requested?.to_s
      }
    end

    def eligibility
      GitlabSubscriptions::PaintedDoorRequestEligibility.new(
        user: user, namespace: container.root_ancestor, feature: :duo_panel
      )
    end
    strong_memoize_attr :eligibility
  end
end
