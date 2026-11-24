# frozen_string_literal: true

module Ai
  class Setting < ApplicationRecord
    self.table_name = "ai_settings"

    include HasRolePermissions
    include CustomizablePermission
    include NormalizesDomainLists

    ignore_column :singleton, remove_with: '19.6', remove_after: '2026-10-16'
    ignore_column :duo_nano_features_enabled, remove_with: '18.3', remove_after: '2025-07-15'
    jsonb_accessor :feature_settings,
      ai_audit_events_streaming_enabled: [:boolean, { default: false }],
      duo_agent_platform_enabled: [:boolean, { default: true }],
      duo_cli_enabled: [:boolean, { default: true }],
      duo_token_usage_tracking_enabled: [:boolean, { default: true }],
      duo_workflow_file_attachments_enabled: [:boolean, { default: false }],
      web_search_enabled: [:boolean, { default: false }]

    validates :feature_settings,
      json_schema: { filename: "ai_setting_feature_settings", size_limit: 64.kilobytes }

    validates :amazon_q_role_arn, length: { maximum: 2048 }, allow_nil: true

    validates :duo_core_features_enabled,
      inclusion: { in: [true, false] },
      if: :will_save_change_to_duo_core_features_enabled?

    belongs_to :organization, class_name: 'Organizations::Organization', optional: false
    validates :organization_id, uniqueness: true

    belongs_to :amazon_q_oauth_application, class_name: 'Authn::OauthApplication', optional: true
    belongs_to :amazon_q_service_account_user, class_name: 'User', optional: true

    belongs_to :duo_workflow_oauth_application, class_name: 'Authn::OauthApplication', optional: true
    belongs_to :duo_workflow_service_account_user, class_name: 'User', optional: true

    after_commit :trigger_todo_creation, on: :update, if: :saved_change_to_duo_core_features_enabled?

    def self.for_organization(organization)
      raise ArgumentError, 'organization is required' unless organization

      # rubocop:disable Performance/ActiveRecordSubtransactionMethods -- creates at most one row per organization
      safe_find_or_create_by(organization_id: organization.id)
      # rubocop:enable Performance/ActiveRecordSubtransactionMethods
    end

    def self.for_organization_read_only(organization)
      raise ArgumentError, 'organization is required' unless organization

      read_only_setting(organization_id: organization.id) || new(organization: organization).tap(&:readonly!)
    end

    def self.for_current_or_default_organization
      # rubocop:disable Gitlab/AvoidCurrentOrganization -- prefer request organization when available
      organization = ::Current.organization if ::Current.organization_assigned
      # rubocop:enable Gitlab/AvoidCurrentOrganization
      # rubocop:disable Gitlab/AvoidDefaultOrganization -- callers outside request context fall back to the default organization
      organization ||= ::Organizations::Organization.default_organization
      # rubocop:enable Gitlab/AvoidDefaultOrganization

      return new.tap(&:readonly!) unless organization

      for_organization_read_only(organization)
    end

    def self.self_hosted?
      ::Ai::SelfHostedModel.any?
    end

    def self.duo_core_features_enabled?(organization)
      !!for_organization_read_only(organization).duo_core_features_enabled
    end

    def self.duo_core_features_enabled_uncached?(organization)
      !!find_by(organization: organization)&.duo_core_features_enabled
    end

    def self.amazon_q_service_account?(user)
      # rubocop:disable Gitlab/AvoidUserOrganization -- user-scoped lookup; in Cells 1.0 a user belongs to exactly one organization
      for_organization_read_only(user.organization).amazon_q_service_account_user_id == user.id
      # rubocop:enable Gitlab/AvoidUserOrganization
    end

    def self.read_only_setting(attributes)
      record_attributes = ::Gitlab::SafeRequestStore.fetch([self, :read_only_setting, attributes]) do
        find_by(attributes)&.attributes
      end

      instantiate(record_attributes)&.tap(&:readonly!) if record_attributes
    end

    private_class_method :read_only_setting

    private

    def trigger_todo_creation
      return if ::Gitlab::Saas.feature_available?(:gitlab_duo_saas_only)
      return unless duo_core_features_enabled?

      GitlabSubscriptions::SelfManaged::DuoCoreTodoNotificationWorker
        .perform_in(GitlabSubscriptions::DuoCore::DELAY_TODO_NOTIFICATION, organization_id)
    end

    def resolve_ai_settings
      self
    end
  end
end
