# frozen_string_literal: true

module Security
  module Concerns
    module ShowsNavIndicator
      extend ActiveSupport::Concern

      private

      def security_nav_indicator_badge(page, namespace)
        return unless ::Security::NavIndicator.visible?(user: context.current_user, namespace: namespace, page: page)

        { label: _('New') }
      end
    end
  end
end
