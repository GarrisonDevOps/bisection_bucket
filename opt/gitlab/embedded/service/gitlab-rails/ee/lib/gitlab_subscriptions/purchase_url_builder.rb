# frozen_string_literal: true

module GitlabSubscriptions
  class PurchaseUrlBuilder
    def initialize(plan_id:, namespace:)
      @plan_id = plan_id
      @namespace = namespace
    end

    def build(params = {})
      if plan_id.blank?
        Gitlab::Routing.url_helpers.promo_pricing_url
      elsif namespace.blank?
        Gitlab::Routing.url_helpers.new_gitlab_subscriptions_group_path(plan_id: plan_id, **params.compact)
      else
        query = params.merge({ plan_id: plan_id, gl_namespace_id: namespace.id }).compact
        Gitlab::Utils.add_url_parameters(Gitlab::Routing.url_helpers.subscription_portal_new_subscription_url, query)
      end
    end

    private

    attr_reader :plan_id, :namespace
  end
end
