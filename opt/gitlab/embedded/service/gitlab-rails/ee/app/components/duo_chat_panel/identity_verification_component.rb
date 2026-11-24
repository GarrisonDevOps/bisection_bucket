# frozen_string_literal: true

module DuoChatPanel
  class IdentityVerificationComponent < ViewComponent::Base
    include DuoChatPanel::LegacyCallout

    def initialize(container:, user:)
      @container = container
      @user = user
    end

    private

    attr_reader :container, :user

    def data
      {
        testid: 'duo-chat-panel-identity-verification',
        identity_verification_required: true.to_s,
        identity_verification_path: ::Gitlab::Routing.url_helpers.identity_verification_path,
        container_type: container.type,
        auto_expand: auto_expanded?(user).to_s
      }.compact
    end
  end
end
