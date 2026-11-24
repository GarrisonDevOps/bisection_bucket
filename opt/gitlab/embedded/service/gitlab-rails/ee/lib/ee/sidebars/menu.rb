# frozen_string_literal: true

module EE
  module Sidebars # rubocop:disable Gitlab/BoundedContexts -- overridden class is not inside a bounded context namespace
    module Menu
      LEGACY_PLAN_TIERS = { License::STARTER_PLAN => :premium }.freeze

      private

      def tier_for(licensed_feature)
        plan = ::GitlabSubscriptions::Features.minimum_plan_for(licensed_feature)
        return if plan.nil?

        LEGACY_PLAN_TIERS.fetch(plan, plan.to_sym)
      end
    end
  end
end
