# frozen_string_literal: true

module GitlabSubscriptions
  class TrackCartAbandonmentService
    def initialize(user:, namespace:, plan:)
      @user = user
      @namespace = namespace
      @plan = plan
    end

    def execute
      return ServiceResponse.error(message: 'User opt-in required') unless user_opted_in?
      return ServiceResponse.error(message: 'Invalid plan') unless valid_plan?

      enqueue_worker

      ServiceResponse.success
    end

    private

    attr_reader :user, :namespace, :plan

    def user_opted_in?
      user.onboarding_status_email_opt_in
    end

    def valid_plan?
      %w[premium ultimate].include?(plan&.downcase)
    end

    def enqueue_worker
      GitlabSubscriptions::CartAbandonmentWorker.perform_in(
        3.hours,
        user.id,
        namespace.id,
        product_interaction,
        current_plan_name
      )
    end

    def product_interaction
      "cart abandonment - SaaS #{plan.capitalize}"
    end

    def current_plan_name
      namespace.actual_plan_name
    end
  end
end
