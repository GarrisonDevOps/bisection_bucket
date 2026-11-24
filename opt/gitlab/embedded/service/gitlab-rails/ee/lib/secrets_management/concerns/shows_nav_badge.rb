# frozen_string_literal: true

module SecretsManagement
  module Concerns
    module ShowsNavBadge
      extend ActiveSupport::Concern

      def secrets_manager_badge
        return unless ::SecretsManagement::NavBadge.visible?(user: context.current_user)

        { label: _('New') }
      end
    end
  end
end
