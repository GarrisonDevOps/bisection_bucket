# frozen_string_literal: true

module GitlabSubscriptions
  class DiscoverComponent < ViewComponent::Base
    include SafeFormatHelper
    include BillingPlansHelper

    def initialize(namespace:)
      @namespace = namespace
    end

    private

    attr_reader :namespace

    delegate :page_title, to: :helpers

    def plans_data
      current_plan = namespace.plan_name_for_upgrading

      GitlabSubscriptions::FetchSubscriptionPlansService
        .new(plan: current_plan, namespace_id: namespace.id)
        .execute
    end

    def buy_now_link
      premium_plan = find_plan(plans_data, ::GitlabSubscriptions::SystemDefined::Plan::PREMIUM)

      plan_purchase_url(namespace, premium_plan)
    end

    def trial_days_remaining
      return 0 unless namespace.trial_active?

      trial_status = GitlabSubscriptions::TrialStatus.new(namespace.trial_starts_on, namespace.trial_ends_on)

      trial_status.days_remaining
    end

    def monthly_commitment_purchased
      @monthly_commitment_purchased ||= fetch_monthly_commitment_purchased
    end

    def has_monthly_commit?
      monthly_commitment_purchased > 0
    end

    def purchase_credits_path
      ::Gitlab::Routing.url_helpers.subscription_portal_gitlab_com_purchase_credits_url(namespace.id)
    end

    def credits_dashboard_path
      helpers.group_settings_gitlab_credits_dashboard_index_path(namespace)
    end

    def dap_credits_card_data
      {
        purchaseCreditsPath: purchase_credits_path,
        creditsDashboardPath: credits_dashboard_path,
        hasMonthlyCommit: has_monthly_commit?,
        creditsGeneralizationUi: ::Feature.enabled?(:credits_generalization_ui, namespace)
      }
    end

    def fetch_monthly_commitment_purchased
      GitlabSubscriptions::FetchMonthlyCommitmentService
        .new(namespace_id: namespace.id)
        .execute
        .payload[:total_credits]
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(e)
      0
    end
  end
end
