# frozen_string_literal: true

module Types
  module SecretsManagement
    class EntitlementType < BaseObject
      graphql_name 'SecretsManagerEntitlement'
      description 'Secrets Manager entitlement for a top-level group, queried through the group or one of its ' \
        'subgroups, or for the instance on GitLab Self-Managed.'

      authorize :read_secrets_manager_entitlement

      # `group` is nil for the instance-wide entitlement (self-managed), so the
      # extractor falls through to the standalone instance boundary.
      authorize_granular_token permissions: :read_secrets_manager,
        boundaries: [
          { boundary: :group, boundary_type: :group },
          { boundary_type: :instance, assignable_when: [:admin, :self_managed] }
        ]

      # `group` is the top-level group the entitlement was resolved for, or nil
      # for the instance-wide entitlement on self-managed. `queried_group` is the
      # group it was queried through, which authorizes it, or nil to use `group`.
      Adapter = Struct.new(:entitlement, :group, :queried_group, keyword_init: true) do
        delegate :state, :blocked_reason, :grace_period_end_date, :trial_started_at, :trial_expires_at,
          :credits_remaining, :credits_total, :on_demand_enabled, :beta_program_ended, :beta_window_eligible,
          :offline_flex_license, to: :entitlement

        def self.declarative_policy_class
          'SecretsManagement::EntitlementPolicy'
        end

        # The state alone cannot tell an air-gapped instance from an online one
        # past its grace window (both resolve to BLOCKED); the license can.
        def offline_license
          return if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

          ::SecretsManagement::InstanceEnrollment.offline_license?
        end
      end

      field :state, ::Types::SecretsManagement::EntitlementStateEnum,
        null: false,
        description: 'Resolved entitlement state.',
        experiment: { milestone: '19.2' }

      field :blocked_reason, ::Types::SecretsManagement::EntitlementBlockedReasonEnum,
        null: true,
        description: 'Reason the entitlement is blocked; null when state is not BLOCKED.',
        experiment: { milestone: '19.2' }

      field :grace_period_end_date, ::Types::DateType,
        null: true,
        description: 'Last day of the read-only grace period, inclusive. Set only when blockedReason is GRACE; ' \
          'null otherwise.'

      # rubocop:disable GraphQL/ExtractType -- these are intentionally top-level fields
      field :trial_started_at, ::Types::TimeType,
        null: true,
        description: 'Timestamp when the Secrets Manager trial started.',
        experiment: { milestone: '19.2' }

      field :trial_expires_at, ::Types::TimeType,
        null: true,
        description: 'Timestamp when the Secrets Manager trial expires.',
        experiment: { milestone: '19.2' }

      field :credits_remaining, GraphQL::Types::Float,
        null: true,
        description: 'Number of trial credits remaining.',
        experiment: { milestone: '19.2' }

      field :credits_total, GraphQL::Types::Float,
        null: true,
        description: 'Initial trial credit allocation for the current trial period.',
        experiment: { milestone: '19.2' }
      # rubocop:enable GraphQL/ExtractType

      field :on_demand_enabled, GraphQL::Types::Boolean,
        null: true,
        description: 'Indicates whether on-demand purchasing is enabled for the namespace.',
        experiment: { milestone: '19.2' }

      # rubocop:disable GraphQL/ExtractType -- flat fields mirror the Entitlement value object the frontend already consumes
      field :beta_program_ended, GraphQL::Types::Boolean,
        null: true,
        description: 'Indicates whether the free-beta program has ended for the namespace. ' \
          'Set only when state is TRIAL_ELIGIBLE; null otherwise.',
        experiment: { milestone: '19.4' }

      field :beta_window_eligible, GraphQL::Types::Boolean,
        null: true,
        description: 'Indicates whether the namespace joined Secrets Manager during the free beta ' \
          'and keeps beta access until the beta program ends. ' \
          'True only when state is TRIAL_ELIGIBLE or INELIGIBLE; false or null otherwise.',
        experiment: { milestone: '19.4' }

      field :offline_license, GraphQL::Types::Boolean,
        null: true,
        description: 'Indicates whether the instance license is not an online cloud license, ' \
          'so no Secrets Manager trial can be started. Null on GitLab.com.',
        experiment: { milestone: '19.4' }

      field :offline_flex_license, GraphQL::Types::Boolean,
        null: true,
        description: 'Indicates whether the offline license is a GitLab Flex license, ' \
          'whose usage consumes GitLab Credits. Null unless state is OFFLINE_PAID.',
        experiment: { milestone: '19.5' }
      # rubocop:enable GraphQL/ExtractType
    end
  end
end
