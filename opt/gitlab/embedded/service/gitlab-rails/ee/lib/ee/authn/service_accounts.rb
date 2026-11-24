# frozen_string_literal: true

module EE
  module Authn
    module ServiceAccounts
      extend ActiveSupport::Concern

      class_methods do
        extend ::Gitlab::Utils::Override

        # Self-managed only: paid EE licenses bypass the free tier limit.
        # Falls back to CE implementation (LIMIT_FOR_FREE check) for unlicensed/free instances.
        override :creation_allowed_for_sm?
        def creation_allowed_for_sm?(_root_namespace = nil)
          return true if paid_sm_license?

          super
        end

        # SaaS only: namespace-scoped check against subscription and free tier limit
        override :creation_allowed_for_saas?
        def creation_allowed_for_saas?(root_namespace)
          return false unless root_namespace

          subscription = root_namespace.gitlab_subscription

          return true if active_paid_subscription?(subscription)

          free_tier_limit_available?(root_namespace)
        end

        # SaaS only
        def free_tier_limit_available?(root_namespace)
          return false unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

          ::Authn::ServiceAccounts::LIMIT_FOR_FREE > all_service_accounts_in_hierarchy_count(root_namespace)
        end

        # Self-managed only: returns true when the instance is on a free/unlicensed plan.
        # Used to enforce stricter rules (e.g., mandatory PAT expiry) on free tier.
        override :free_tier?
        def free_tier?(_root_namespace = nil)
          !paid_sm_license?
        end

        # SaaS only: returns true when the namespace is on free tier
        # (no active paid subscription and not on trial).
        override :free_tier_namespace?
        def free_tier_namespace?(namespace)
          return false unless namespace

          root = namespace.root_ancestor
          return false if root.trial_active?

          !active_paid_subscription?(root.gitlab_subscription)
        end

        # rubocop: disable CodeReuse/ActiveRecord -- optimized query to count all service accounts
        # (including composite identity) across group hierarchy for free tier limit.
        def all_service_accounts_in_hierarchy_count(root_namespace)
          return 0 unless root_namespace

          namespace_ids = root_namespace.self_and_descendant_ids

          group_provisioned_scope = ::User
            .service_accounts
            .with_provisioning_group(namespace_ids)
            .select(:id)

          project_ids = ::Project.where(namespace_id: namespace_ids).select(:id)
          project_provisioned_scope = ::User
            .service_accounts
            .joins(:user_detail)
            .where(user_details: { provisioned_by_project_id: project_ids })
            .select(:id)

          ::User.from_union([group_provisioned_scope, project_provisioned_scope], remove_duplicates: false).count
        end
        # rubocop: enable CodeReuse/ActiveRecord

        private

        def paid_sm_license?
          ::License.current&.ultimate? || ::License.current&.premium?
        end

        def active_paid_subscription?(subscription)
          subscription && !subscription.expired? &&
            ::GitlabSubscriptions::SystemDefined::Plan::PAID_HOSTED_PLANS.include?(subscription.plan_name)
        end
      end
    end
  end
end
