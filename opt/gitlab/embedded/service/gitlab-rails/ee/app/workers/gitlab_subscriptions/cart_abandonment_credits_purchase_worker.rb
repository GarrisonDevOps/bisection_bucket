# frozen_string_literal: true

module GitlabSubscriptions
  class CartAbandonmentCreditsPurchaseWorker
    include ApplicationWorker
    include GitlabSubscriptions::CartAbandonmentConcern

    data_consistency :sticky
    idempotent!
    loggable_arguments 0, 1, 2

    def perform(user_id, namespace_id, previous_monthly_commitment_credits)
      user, namespace = find_user_and_namespace(user_id, namespace_id)

      return unless user && namespace

      return if purchased_credits?(namespace, previous_monthly_commitment_credits.to_i)

      send_cart_abandonment_lead(user, build_lead_params(user, namespace, previous_monthly_commitment_credits.to_i))
    end

    private

    def purchased_credits?(namespace, previous_monthly_commitment_credits)
      return true if previous_monthly_commitment_credits == 0 && namespace.has_active_gitlab_credits_add_on?

      response = GitlabSubscriptions::FetchMonthlyCommitmentService
        .new(namespace_id: namespace.id)
        .execute

      response.payload[:total_credits].to_i > previous_monthly_commitment_credits
    end

    def build_lead_params(user, namespace, previous_monthly_commitment_credits)
      build_base_lead_params(user, namespace).merge(
        product_interaction: 'cart abandonment - DAP monthly commit',
        glm_source: 'gitlab.com',
        glm_content: previous_monthly_commitment_credits == 0 ? 'first-purchase-credits' : 'increase-credits-purchase'
      )
    end
  end
end
