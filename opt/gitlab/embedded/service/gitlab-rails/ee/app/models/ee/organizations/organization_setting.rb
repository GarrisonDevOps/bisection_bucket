# frozen_string_literal: true

module EE
  module Organizations
    module OrganizationSetting
      extend ActiveSupport::Concern

      prepended do
        # No jsonb default: a non-empty defaults mapping on this second
        # jsonb_accessor call would shadow the CE call's mapping and drop
        # restricted_visibility_levels' default from newly written rows. An
        # absent key already reads as not opted in.
        jsonb_accessor :settings,
          security_tracked_context_quota: :integer,
          policy_store_experiment_enabled: :boolean

        validates :security_tracked_context_quota,
          numericality: { only_integer: true, greater_than_or_equal_to: 1, allow_nil: true }
      end

      def security_tracked_context_quota_with_default
        return security_tracked_context_quota if security_tracked_context_quota.present?
        return unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        ::Gitlab::CurrentSettings.default_security_tracked_context_quota || 2
      end

      def security_tracked_context_quota_explicitly_set?
        security_tracked_context_quota.present?
      end
    end
  end
end
