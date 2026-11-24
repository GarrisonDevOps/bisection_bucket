# frozen_string_literal: true

module EE
  module ServiceDesk
    module CustomTemplates
      extend ::Gitlab::Utils::Override

      # Restricted only when every condition holds, so the default is always
      # to keep custom templates working:
      #
      # - GitLab.com only. There is no threshold to neutralize the way the
      #   email rate limiter uses a plan_limits value of 0, so self-managed
      #   has to be excluded explicitly.
      # - Namespaces created before the cutoff are grandfathered. created_at
      #   is immutable, so a later trial or downgrade cannot move a namespace
      #   into the restriction.
      # - Paid non-trial plans are exempt. The predicate is evaluated per
      #   send, so upgrading lifts the restriction with no state to migrate.
      # - The feature flag gates the rollout and is removed once enforcement
      #   is fully live.
      #
      # The boundary is paid vs free, not group vs personal: a group without a
      # subscription is restricted too. Personal namespaces resolve to the free
      # plan and cannot hold a subscription on GitLab.com, so post-cutoff they
      # stay restricted with no upgrade path. That is intentional, they are the
      # cheapest namespace to create and the main abuse surface here.
      override :enabled?
      def enabled?
        return true unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        return true if root_namespace.created_at < ::ServiceDesk::CustomTemplates::RESTRICTED_FROM_DATE
        return true if root_namespace.actual_plan.paid_excluding_trials?
        return true unless ::Feature.enabled?(:service_desk_restrict_custom_templates, root_namespace, type: :wip)

        false
      end

      private

      def root_namespace
        project.root_namespace
      end
    end
  end
end
