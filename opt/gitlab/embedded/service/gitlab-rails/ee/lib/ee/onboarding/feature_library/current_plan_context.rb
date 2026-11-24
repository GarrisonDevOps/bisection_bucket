# frozen_string_literal: true

module EE
  module Onboarding
    module FeatureLibrary
      module CurrentPlanContext
        extend ::Gitlab::Utils::Override

        TRIAL_PLANS = (
          ::GitlabSubscriptions::SystemDefined::Plan::FREE_TRIAL_PLANS +
          [::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE_TRIAL_PAID_CUSTOMER]
        ).freeze
        # Retired plans with fewer features than Premium, so they count as Free here.
        RETIRED_PLANS = [::GitlabSubscriptions::SystemDefined::Plan::BRONZE, ::License::STARTER_PLAN].freeze

        override :edition
        def edition
          :ee
        end

        override :deployment
        def deployment
          saas? ? :saas : super
        end

        override :current_plan
        def current_plan
          saas? ? tier_for(namespace_plan_name) : tier_for(license_plan_name)
        end

        override :trial?
        def trial?
          saas? ? TRIAL_PLANS.include?(namespace_plan_name) : !!usable_license&.trial?
        end

        # A trial compares against the plan the viewer returns to when it ends.
        override :base_plan
        def base_plan
          return super unless trial?

          saas? ? namespace_trial_base_plan : license_trial_base_plan
        end

        private

        def saas?
          ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        end

        def tier_for(plan_name)
          return :free if RETIRED_PLANS.include?(plan_name)

          ::GitlabSubscriptions::SystemDefined::Plan.tier_for(plan_name).to_sym
        end

        def root_namespace
          resource&.root_ancestor
        end

        # The hosted plan name carries the trial state, so the plan and trial can't disagree
        # between a trial's end date and CustomersDot downgrading the plan.
        def namespace_plan_name
          root_namespace&.actual_plan_name
        end

        # A Premium customer trialing Ultimate returns to Premium, a Free customer trialing Ultimate returns to Free.
        # Only reached when trial? is true, which needs a root namespace with a trial plan.
        def namespace_trial_base_plan
          root_namespace.ultimate_trial_paid_customer_plan? ? :premium : :free
        end

        # Mirrors License#feature_available?: an expired trial license unlocks nothing, but an
        # expired paid license still unlocks its plan.
        def usable_license
          license = ::License.current
          return if license.nil? || (license.trial? && license.expired?)

          license
        end

        def license_plan_name
          usable_license&.plan
        end

        # While a trial license is current, the paid license underneath it is what the instance returns to.
        def license_trial_base_plan
          paid_license = ::License.billable_license
          return :free if paid_license.nil? || paid_license.trial?

          tier_for(paid_license.plan)
        end
      end
    end
  end
end
