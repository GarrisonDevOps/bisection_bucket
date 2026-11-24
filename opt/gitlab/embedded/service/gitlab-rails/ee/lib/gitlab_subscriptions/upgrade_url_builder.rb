# frozen_string_literal: true

module GitlabSubscriptions
  # Builds the CustomersDot upgrade URL for an upgradable namespace, falling
  # back to the standard purchase URL when the namespace cannot be upgraded.
  # Keeping this separate from PurchaseUrlBuilder isolates the upgrade routing
  # so standard purchase flows are never sent to the upgrade page.
  class UpgradeUrlBuilder
    def initialize(plan_id:, namespace:)
      @plan_id = plan_id
      @namespace = namespace
    end

    def build(params = {})
      return purchase_url(params) unless upgradable?

      Gitlab::Utils.add_url_parameters(
        Gitlab::Routing.url_helpers.subscription_portal_upgrade_subscription_url(namespace.id, plan_id),
        params.compact)
    end

    private

    attr_reader :plan_id, :namespace

    def upgradable?
      plan_id.present? && namespace.present? && namespace.upgradable?
    end

    def purchase_url(params)
      PurchaseUrlBuilder.new(plan_id: plan_id, namespace: namespace).build(params)
    end
  end
end
