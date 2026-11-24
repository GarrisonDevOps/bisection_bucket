# frozen_string_literal: true

module GitlabSubscriptions
  class CartAbandonmentWorker
    include ApplicationWorker
    include GitlabSubscriptions::CartAbandonmentConcern

    data_consistency :sticky
    idempotent!
    loggable_arguments 0, 1, 2, 3

    PRODUCT_INTERACTION_TO_PLAN = {
      'cart abandonment - SaaS Premium' => 'premium',
      'cart abandonment - SaaS Ultimate' => 'ultimate'
    }.freeze

    def perform(user_id, namespace_id, product_interaction, previous_plan_name)
      user, namespace = find_user_and_namespace(user_id, namespace_id)

      return unless user && namespace

      return if purchased_paid_plan?(namespace, previous_plan_name)

      send_cart_abandonment_lead(user, build_lead_params(user, namespace, product_interaction))
    end

    private

    def purchased_paid_plan?(namespace, previous_plan_name)
      current_plan_name = namespace.actual_plan_name
      paid_plans = %w[premium ultimate]

      return false if previous_plan_name == current_plan_name

      paid_plans.include?(current_plan_name&.downcase)
    end

    def build_lead_params(user, namespace, product_interaction)
      build_base_lead_params(user, namespace).merge(
        product_interaction: product_interaction,
        plan_id: plan_id_for_selected_plan(product_interaction, namespace)
      )
    end

    def plan_id_for_selected_plan(product_interaction, namespace)
      selected_plan = PRODUCT_INTERACTION_TO_PLAN[product_interaction]
      plans_data = GitlabSubscriptions::FetchSubscriptionPlansService.new(
        plan: namespace.plan_name_for_upgrading,
        namespace_id: namespace.id
      ).execute

      return unless plans_data

      plans_data.detect { |plan| plan.code == selected_plan }&.id
    end
  end
end
