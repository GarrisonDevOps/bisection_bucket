# frozen_string_literal: true

module EE
  module Onboarding
    module FeatureLibrary
      module UpgradeCta
        extend ::Gitlab::Utils::Override

        override :build
        def build
          # On GitLab.com every CTA belongs to a namespace, so there's nothing to offer without one.
          return if saas? && root_namespace.nil?
          return unless eligible_to_purchase?
          return talk_to_sales_cta if purchased_gitlab_credits?

          saas? ? saas_upgrade_cta : self_managed_upgrade_cta
        end

        private

        # Only someone who can start a purchase gets a CTA: group owners on GitLab.com,
        # instance admins on self-managed. Other viewers see the pages without one.
        def eligible_to_purchase?
          return false unless user

          saas? ? Ability.allowed?(user, :edit_billing, root_namespace) : user.can_admin_all_resources?
        end

        def purchased_gitlab_credits?
          ::GitlabSubscriptions::AddOnPurchase.purchased_gitlab_credits_exist?(saas? ? root_namespace : :instance)
        end

        def talk_to_sales_cta
          cta = { type: 'talk_to_sales', text: s_('FeatureLibrary|Talk to sales') }

          saas? ? cta.merge(hand_raise_lead: hand_raise_lead) : cta.merge(url: sales_url)
        end

        def hand_raise_lead
          {
            glm_content: "feature_catalog_#{plan}",
            cta_tracking: { action: 'click_button', label: 'feature_catalog_talk_to_sales', property: plan.to_s }
          }
        end

        def sales_url
          url_helpers.promo_url(path: '/sales/')
        end

        def saas_upgrade_cta
          return saas_tier_upgrade_cta if base_plan == :premium

          # Personal namespaces can't hold a subscription. Without a namespace id, the purchase
          # flow routes to group selection or creation first.
          namespace_id = root_namespace.user_namespace? ? nil : root_namespace.id

          upgrade_cta(unified_purchase_url('gitlab_com', gl_namespace_id: namespace_id))
        end

        # The unified purchase flow only adds a base product; it rejects a namespace that already
        # has one. A Premium base plan means a Premium subscription exists, including during an
        # Ultimate trial, when GitlabSubscription#upgradable? is false.
        def saas_tier_upgrade_cta
          # An expired subscription stays upgradable in place until CustomersDot downgrades the
          # namespace, which happens before the upgrade grace period ends.
          plan_id = saas_plan_id
          return upgrade_cta(billings_url) unless plan_id

          upgrade_cta(url_helpers.subscription_portal_upgrade_subscription_url(root_namespace.id, plan_id))
        end

        def saas_plan_id
          plans = ::GitlabSubscriptions::FetchSubscriptionPlansService
            .new(plan: root_namespace.plan_name_for_upgrading, namespace_id: root_namespace.id)
            .execute

          plans&.find { |candidate| candidate.code == plan.to_s }&.id
        end

        # The Billing page holds the in-product Upgrade button.
        def billings_url
          return url_helpers.profile_billings_url if root_namespace.user_namespace?

          url_helpers.group_billings_url(root_namespace)
        end

        def self_managed_upgrade_cta
          license = subscription_license

          # Offline instances buy through sales; cloud and legacy licenses upgrade self-serve.
          return talk_to_sales_cta if license&.offline_cloud_license?

          if premium_license_in_grace_period?(license)
            # A license without a subscription name is typically issued by hand, with no
            # Customers Portal subscription to upgrade.
            return talk_to_sales_cta if license.subscription_name.blank?

            return upgrade_cta(url_helpers.subscription_portal_upgrade_self_managed_subscription_url(
              license.subscription_name
            ))
          end

          upgrade_cta(unified_purchase_url('self_managed'))
        end

        # The paid license the instance's subscription belongs to. During a trial that's the paid
        # license underneath it, if any, so CTAs never point at the trial subscription.
        def subscription_license
          license = ::License.current
          return license unless license&.trial?

          paid_license = ::License.billable_license
          paid_license unless paid_license.nil? || paid_license.trial?
        end

        def premium_license_in_grace_period?(license)
          base_plan == :premium && license.present? && !license.grace_period_expired?
        end

        # CustomersDot only records entry_point values listed in
        # Subscriptions::Purchases::Tracking::ENTRY_POINTS, so keep the two in step.
        def unified_purchase_url(deployment_type, gl_namespace_id: nil)
          params = {
            deployment_type: deployment_type,
            plan_type: 'base_product',
            tier: plan,
            gl_namespace_id: gl_namespace_id,
            entry_point: 'feature_catalog'
          }.compact

          ::Gitlab::Utils.add_url_parameters(url_helpers.subscription_portal_new_purchase_url, params)
        end

        def upgrade_cta(url)
          { type: 'upgrade', text: upgrade_text, url: url }
        end

        def upgrade_text
          if plan == :ultimate
            s_('FeatureLibrary|Upgrade to Ultimate')
          else
            s_('FeatureLibrary|Upgrade to Premium')
          end
        end

        def saas?
          ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        end

        def url_helpers
          ::Gitlab::Routing.url_helpers
        end

        def root_namespace
          resource&.root_ancestor
        end
      end
    end
  end
end
