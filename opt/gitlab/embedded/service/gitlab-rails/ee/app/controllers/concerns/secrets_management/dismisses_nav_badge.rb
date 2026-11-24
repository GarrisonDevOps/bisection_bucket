# frozen_string_literal: true

module SecretsManagement
  module DismissesNavBadge
    extend ActiveSupport::Concern

    private

    def dismiss_secrets_manager_badge
      return unless ::SecretsManagement::NavBadge.visible?(user: current_user)

      ::Users::DismissCalloutService.new(
        container: nil,
        current_user: current_user,
        params: { feature_name: ::SecretsManagement::NavBadge::CALLOUT_FEATURE_NAME }
      ).execute
    end
  end
end
