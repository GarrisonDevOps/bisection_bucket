# frozen_string_literal: true

module GitlabSubscriptions
  class SubscriptionUsage
    include ::Gitlab::Utils::StrongMemoize

    MonthlyWaiver = Struct.new(:total_credits, :credits_used, :daily_usage, :declarative_policy_subject)
    MonthlyCommitment = Struct.new(:total_credits, :credits_used, :daily_usage, :declarative_policy_subject)
    Overage = Struct.new(:is_allowed, :credits_used, :daily_usage, :declarative_policy_subject)
    DailyUsage = Struct.new(:date, :credits_used, :declarative_policy_subject)
    PaidTierTrial = Struct.new(:is_active, :daily_usage, :declarative_policy_subject)
    Product = Struct.new(:id, :title, :credits_used, :flow_types, :declarative_policy_subject)
    ProductFlowType = Struct.new(:id, :title, :declarative_policy_subject)
    NonBillableUsage = Struct.new(
      :product_id, :skip_reason, :total_credits_used, :daily_usage, :declarative_policy_subject
    )

    def initialize(
      subscription_target:,
      subscription_usage_client:,
      namespace: nil,
      organization: nil,
      flow_types: nil
    )
      @subscription_target = subscription_target
      @namespace = namespace
      @organization = organization
      @subscription_usage_client = subscription_usage_client
      @flow_types = flow_types
    end

    attr_reader :namespace, :organization, :subscription_usage_client, :subscription_target, :flow_types

    def enabled?
      !!usage_metadata[:enabled]
    end

    def outdated_client?
      usage_metadata[:isOutdatedClient]
    end

    def start_date
      usage_metadata[:startDate]
    end

    def end_date
      usage_metadata[:endDate]
    end

    def last_event_transaction_at
      usage_metadata[:lastEventTransactionAt]
    end

    def purchase_credits_path
      return unless enabled?
      # The path carries the nominated group's ID, which must not reach an Organization's client.
      return if organization

      is_gitlab_com = ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      return if is_gitlab_com && namespace.nil?

      billable_license = License.billable_license unless is_gitlab_com
      return if !is_gitlab_com && billable_license&.subscription_name.nil?

      deployment_type = is_gitlab_com ? 'gitlab_com' : 'self_managed'
      params = {
        deployment_type: deployment_type,
        plan_type: 'gitlab_credits',
        gl_namespace_id: is_gitlab_com ? namespace.root_ancestor&.id : nil,
        subscription_name: is_gitlab_com ? nil : billable_license.subscription_name
      }.compact

      "/subscriptions/purchases/gitlab?#{params.to_query}"
    end

    def overage_terms_accepted
      !!usage_metadata[:overageTermsAccepted]
    end

    def can_accept_overage_terms
      !!usage_metadata[:canAcceptOverageTerms]
    end

    def dap_promo_enabled
      !!usage_metadata[:dapPromoEnabled]
    end

    def usage_dashboard_path
      usage_metadata[:usageDashboardPath]
    end

    def credits_used
      strong_memoize_with(:credits_used, flow_types) do
        response = usage_summary
        next unless response[:success]

        response.dig(:subscriptionUsage, :creditsUsed)
      end
    end

    def daily_usage(sort: :date_asc, limit: nil)
      strong_memoize_with(:daily_usage, sort, limit, flow_types) do
        max_days = max_days_in_range

        next [] if max_days == 0

        effective_limit =
          if limit
            validate_daily_usage_limit!(limit, max_days)
            limit
          else
            max_days
          end

        response = subscription_usage(sort: sort, limit: effective_limit, flow_types: flow_types)
        next unless response[:success]

        build_daily_usage(response.dig(:subscriptionUsage, :dailyUsage))
      end
    end

    def daily_average
      strong_memoize_with(:daily_average, flow_types) do
        response = usage_summary
        next unless response[:success]

        response.dig(:subscriptionUsage, :dailyAverage)
      end
    end

    def monthly_waiver
      monthly_waiver_response = subscription_usage_client.get_monthly_waiver

      return unless monthly_waiver_response[:success]

      MonthlyWaiver.new(
        total_credits: monthly_waiver_response.dig(:monthlyWaiver, :totalCredits),
        credits_used: monthly_waiver_response.dig(:monthlyWaiver, :creditsUsed),
        daily_usage: build_daily_usage(monthly_waiver_response.dig(:monthlyWaiver, :dailyUsage)),
        declarative_policy_subject: self
      )
    end
    strong_memoize_attr :monthly_waiver

    def monthly_commitment
      monthly_commitment_response = subscription_usage_client.get_monthly_commitment

      return unless monthly_commitment_response[:success]

      MonthlyCommitment.new(
        total_credits: monthly_commitment_response.dig(:monthlyCommitment, :totalCredits),
        credits_used: monthly_commitment_response.dig(:monthlyCommitment, :creditsUsed),
        daily_usage: build_daily_usage(monthly_commitment_response.dig(:monthlyCommitment, :dailyUsage)),
        declarative_policy_subject: self
      )
    end
    strong_memoize_attr :monthly_commitment

    def overage
      overage_usage_response = subscription_usage_client.get_overage

      return unless overage_usage_response[:success]

      Overage.new(
        is_allowed: overage_usage_response.dig(:overage, :isAllowed),
        credits_used: overage_usage_response.dig(:overage, :creditsUsed),
        daily_usage: build_daily_usage(overage_usage_response.dig(:overage, :dailyUsage)),
        declarative_policy_subject: self
      )
    end
    strong_memoize_attr :overage

    def budget_caps
      SubscriptionsUsage::BudgetCaps.new(subscription_usage: self)
    end
    strong_memoize_attr :budget_caps

    def users_usage
      SubscriptionsUsage::UserUsage.new(
        subscription_usage: self
      )
    end
    strong_memoize_attr :users_usage

    def subscription_portal_usage_dashboard_url
      return unless can_accept_overage_terms

      path = usage_dashboard_path
      return if path.blank?

      "#{::Gitlab::SubscriptionPortal.default_production_customer_portal_url}#{path}"
    end
    strong_memoize_attr :subscription_portal_usage_dashboard_url

    def paid_tier_trial
      paid_tier_trial_response = subscription_usage_client.get_paid_tier_trial

      PaidTierTrial.new(
        is_active: !!paid_tier_trial_response.dig(:paidTierTrial, :isActive),
        daily_usage: build_daily_usage(paid_tier_trial_response.dig(:paidTierTrial, :dailyUsage)),
        declarative_policy_subject: self
      )
    end
    strong_memoize_attr :paid_tier_trial

    def products
      products_response = subscription_usage_client.get_products

      return unless products_response[:success]

      build_products(products_response[:products])
    end
    strong_memoize_attr :products

    def non_billable_usage
      strong_memoize_with(:non_billable_usage, flow_types) do
        response = subscription_usage_client.get_non_billable_usage(flow_types: flow_types)
        next unless response[:success]

        build_non_billable_usage(response[:nonBillableUsage])
      end
    end

    private

    def build_products(products)
      products.to_a.map do |product|
        Product.new(
          id: product[:id],
          title: product[:title],
          credits_used: product[:creditsUsed],
          flow_types: build_product_flow_types(product[:flowTypes]),
          declarative_policy_subject: self
        )
      end
    end

    def build_product_flow_types(flow_types)
      flow_types.to_a.map do |flow_type|
        ProductFlowType.new(
          id: flow_type[:id],
          title: flow_type[:title],
          declarative_policy_subject: self
        )
      end
    end

    def build_non_billable_usage(non_billable_usage)
      non_billable_usage.to_a.map do |usage|
        NonBillableUsage.new(
          product_id: usage[:productId],
          skip_reason: usage[:skipReason],
          total_credits_used: usage[:totalCreditsUsed],
          daily_usage: build_daily_usage(usage[:dailyUsage]),
          declarative_policy_subject: self
        )
      end
    end

    def build_daily_usage(daily_usage)
      daily_usage.to_a.map do |usage|
        DailyUsage.new(
          date: usage[:date],
          credits_used: usage[:creditsUsed],
          declarative_policy_subject: self
        )
      end
    end

    def usage_metadata
      subscription_usage_client.get_metadata[:subscriptionUsage] || {}
    end
    strong_memoize_attr :usage_metadata

    def subscription_usage(args = {})
      strong_memoize_with(:subscription_usage, args) do
        subscription_usage_client.get_subscription_usage(args) || {}
      end
    end

    def usage_summary
      max_days = max_days_in_range
      return subscription_usage(flow_types: flow_types) if max_days == 0

      subscription_usage(sort: :date_asc, limit: max_days, flow_types: flow_types)
    end

    def max_days_in_range
      client_start_date = subscription_usage_client.start_date
      client_end_date = subscription_usage_client.end_date

      [(Date.parse(client_end_date.to_s) - Date.parse(client_start_date.to_s)).to_i + 1, 0].max
    end

    def validate_daily_usage_limit!(limit, max_days)
      return unless limit > max_days

      raise Gitlab::Graphql::Errors::ArgumentError,
        "limit cannot exceed the number of days in the date range (#{max_days})"
    end
  end
end
