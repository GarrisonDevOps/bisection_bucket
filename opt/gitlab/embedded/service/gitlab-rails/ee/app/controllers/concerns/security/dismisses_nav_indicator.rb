# frozen_string_literal: true

module Security
  module DismissesNavIndicator
    extend ActiveSupport::Concern

    private

    def dismiss_security_nav_indicator(page, namespace)
      return unless request.format.html?
      return unless ::Security::NavIndicator.visible?(user: current_user, namespace: namespace, page: page)

      ::Users::DismissCalloutService.new(
        container: nil,
        current_user: current_user,
        params: { feature_name: ::Security::NavIndicator::CALLOUT_FEATURE_NAMES.fetch(page) }
      ).execute
    end
  end
end
