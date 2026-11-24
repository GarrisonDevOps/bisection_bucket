# frozen_string_literal: true

module GitlabSubscriptions
  class EndOfTrialModalComponent < ViewComponent::Base
    include ::Gitlab::Utils::StrongMemoize

    FEATURE_NAME = 'end_of_trial_modal'
    private_constant :FEATURE_NAME

    def initialize(user:, namespace:)
      @user = user
      @namespace = namespace
    end

    private

    attr_reader :user, :namespace

    def render?
      return false unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      return false unless Ability.allowed?(user, :read_billing, namespace)
      return false unless ::GitlabSubscriptions::Trials.recently_expired?(namespace)
      return false if user.dismissed_callout_for_group?(feature_name: FEATURE_NAME, group: namespace)

      plans_data.present?
    end

    def plans_data
      GitlabSubscriptions::FetchSubscriptionPlansService.new(
        plan: namespace.plan_name_for_upgrading,
        namespace_id: namespace.id
      ).execute
    end
    strong_memoize_attr :plans_data

    def plan_purchase_url(plan)
      GitlabSubscriptions::PurchaseUrlBuilder.new(plan_id: plan.id, namespace: namespace).build
    end

    def find_plan(plans_data, plan_code)
      plans_data.find { |plan| plan.code == plan_code }
    end

    def view_model
      attrs = {
        featureName: FEATURE_NAME,
        groupId: namespace.id,
        groupName: namespace.name,
        explorePlansPath: group_billings_path(namespace),
        upgradeUrl: plan_purchase_url(find_plan(plans_data, ::GitlabSubscriptions::SystemDefined::Plan::PREMIUM)),
        purchaseCreditsUrl: ::Gitlab::Routing.url_helpers
          .subscription_portal_gitlab_com_purchase_credits_url(namespace.id),
        hasMonthlyCreditCommitment: monthly_commitment_purchased > 0,
        creditsGeneralizationUi: ::Feature.enabled?(:credits_generalization_ui, namespace)
      }

      ::Gitlab::Json.generate(attrs)
    end

    def monthly_commitment_purchased
      GitlabSubscriptions::FetchMonthlyCommitmentService
        .new(namespace_id: namespace.id).execute.payload[:total_credits]
    rescue StandardError
      0
    end
  end
end
