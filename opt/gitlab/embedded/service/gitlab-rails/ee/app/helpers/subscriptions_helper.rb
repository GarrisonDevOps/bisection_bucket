# frozen_string_literal: true

module SubscriptionsHelper
  include ::Gitlab::Utils::StrongMemoize

  def plan_title
    return if params[:plan_id].blank?

    strong_memoize(:plan_title) do
      plan = subscription_available_plans.find { |plan| plan[:id] == params[:plan_id] }
      plan[:code].titleize if plan
    end
  end

  def present_groups(groups)
    groups.map { |namespace| present_group(namespace) }
  end

  private

  def plans_data
    GitlabSubscriptions::FetchSubscriptionPlansService.new(plan: :free).execute
      .map(&:symbolize_keys)
      .reject { |plan_data| plan_data[:free] }
      .map do |plan_data|
        plan_data.slice(
          :id,
          :code,
          :price_per_year,
          :eligible_to_use_promo_code,
          :deprecated,
          :name,
          :hide_card
        )
      end
  end

  def subscription_available_plans
    plans_data.reject { |plan_data| plan_data[:deprecated] || plan_data[:hide_card] }
  end

  def present_group(namespace)
    {
      id: namespace.id,
      name: namespace.name,
      full_path: namespace.full_path
    }
  end
end

SubscriptionsHelper.prepend_mod
