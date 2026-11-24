# frozen_string_literal: true

module EE
  module GitlabSubscriptions
    module SystemDefined
      module Plan
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        FREE = 'free'
        BRONZE = 'bronze'
        SILVER = 'silver'
        PREMIUM = 'premium'
        GOLD = 'gold'
        ULTIMATE = 'ultimate'
        ULTIMATE_TRIAL = 'ultimate_trial'
        ULTIMATE_TRIAL_PAID_CUSTOMER = 'ultimate_trial_paid_customer'
        PREMIUM_TRIAL = 'premium_trial'
        OPEN_SOURCE = 'opensource'

        # 'default' is spelled out to avoid a load-time reference to the CE
        # class; the parity specs guard against drift from the CE DEFAULT.
        EE_DEFAULT_PLANS = ['default', FREE].freeze
        PAID_HOSTED_PLANS = [
          BRONZE,
          SILVER,
          PREMIUM,
          GOLD,
          ULTIMATE,
          ULTIMATE_TRIAL,
          ULTIMATE_TRIAL_PAID_CUSTOMER,
          PREMIUM_TRIAL,
          OPEN_SOURCE
        ].freeze
        FREE_TRIAL_PLANS = [ULTIMATE_TRIAL, PREMIUM_TRIAL].freeze
        EE_ALL_PLANS = (EE_DEFAULT_PLANS + PAID_HOSTED_PLANS).freeze
        PLANS_ELIGIBLE_FOR_TRIAL = (EE_DEFAULT_PLANS | [PREMIUM]).freeze
        TOP_PLANS = [GOLD, ULTIMATE, OPEN_SOURCE].freeze
        CURRENT_ACTIVE_PLANS = [FREE, PREMIUM, ULTIMATE].freeze
        ULTIMATE_TRIAL_PLANS = [ULTIMATE_TRIAL, ULTIMATE_TRIAL_PAID_CUSTOMER].freeze
        ALL_ULTIMATE_PLANS = [ULTIMATE, *ULTIMATE_TRIAL_PLANS].freeze

        # A tier is the bucket a plan sells into, so every plan collapses onto one of
        # three. Ordered, because callers rank tiers by TIERS.index.
        TIERS = [FREE, PREMIUM, ULTIMATE].freeze
        ULTIMATE_TIER_PLANS = (TOP_PLANS + ULTIMATE_TRIAL_PLANS).freeze
        PREMIUM_TIER_PLANS = (PAID_HOSTED_PLANS - ULTIMATE_TIER_PLANS).freeze

        private_constant :EE_ALL_PLANS, :EE_DEFAULT_PLANS

        class_methods do
          extend ::Gitlab::Utils::Override

          override :all_plans
          def all_plans
            EE_ALL_PLANS
          end

          override :default_plans
          def default_plans
            EE_DEFAULT_PLANS
          end

          override :instance_plans
          def instance_plans
            return super unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

            all
          end

          def tier_for(plan_name)
            return ULTIMATE if ULTIMATE_TIER_PLANS.include?(plan_name)
            return PREMIUM if PREMIUM_TIER_PLANS.include?(plan_name)

            FREE
          end

          # Mirrors EE::Plan.free, guard included: nil off GitLab.com. Namespace#actual_plan=
          # relies on that nil to fall back to Plan.default on self-managed.
          def free
            return unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

            find_by!(name: FREE)
          end
        end

        override :paid?
        def paid?
          PAID_HOSTED_PLANS.include?(name)
        end

        override :ultimate_or_ultimate_trial_plans?
        def ultimate_or_ultimate_trial_plans?
          ALL_ULTIMATE_PLANS.include?(name)
        end

        def paid_excluding_trials?(exclude_oss: false)
          paid_hosted_plans = PAID_HOSTED_PLANS.dup
          paid_hosted_plans.delete(OPEN_SOURCE) if exclude_oss
          (paid_hosted_plans - FREE_TRIAL_PLANS).include?(name)
        end

        def open_source?
          name == OPEN_SOURCE
        end
      end
    end
  end
end
