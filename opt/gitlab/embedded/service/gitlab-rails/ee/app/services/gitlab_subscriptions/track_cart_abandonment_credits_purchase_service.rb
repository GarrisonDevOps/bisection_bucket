# frozen_string_literal: true

module GitlabSubscriptions
  class TrackCartAbandonmentCreditsPurchaseService
    def initialize(user:, namespace:, monthly_commitment_credits:)
      @user = user
      @namespace = namespace
      @monthly_commitment_credits = monthly_commitment_credits
    end

    def execute
      return ServiceResponse.error(message: 'User opt-in required to track credits purchase') unless user_opted_in?

      credits = previous_monthly_commitment_credits
      return ServiceResponse.error(message: 'Monthly commitment unavailable') if credits.nil?

      enqueue_worker(credits)

      ServiceResponse.success
    end

    private

    attr_reader :user, :namespace, :monthly_commitment_credits

    def user_opted_in?
      user.onboarding_status_email_opt_in
    end

    def previous_monthly_commitment_credits
      return monthly_commitment_credits unless Feature.enabled?(:cart_abandonment_server_side_credits, namespace)

      response = GitlabSubscriptions::FetchMonthlyCommitmentService
        .new(namespace_id: namespace.id, cache_mode: :read)
        .execute

      response.payload[:total_credits] if response.success?
    rescue ::Gitlab::SubscriptionPortal::SubscriptionUsageClient::ResponseError
      # The client already reports these to error tracking.
      nil
    rescue StandardError => e
      ::Gitlab::ErrorTracking.track_exception(e, namespace_id: namespace.id)
      nil
    end

    def enqueue_worker(credits)
      GitlabSubscriptions::CartAbandonmentCreditsPurchaseWorker.perform_in(
        3.hours,
        user.id,
        namespace.id,
        credits
      )
    end
  end
end
