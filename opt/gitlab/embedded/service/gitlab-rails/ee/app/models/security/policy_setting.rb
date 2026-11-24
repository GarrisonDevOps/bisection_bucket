# frozen_string_literal: true

module Security
  class PolicySetting < ApplicationRecord
    self.table_name = 'security_policy_settings'

    CSP_NAMESPACE_LOCK_DURATION = 10.minutes

    validates :csp_namespace, top_level_group: true
    validates :organization, uniqueness: true

    validate :validate_csp_is_group
    validate :validate_csp_namespace_unlocked, if: :will_save_change_to_csp_namespace_id?
    validate :validate_csp_namespace_organization, if: :assigning_csp_namespace?

    # A group for managing Centralized Security Policies
    belongs_to :organization, class_name: 'Organizations::Organization'
    belongs_to :csp_namespace, class_name: 'Group', optional: true

    before_save :set_csp_namespace_lock, if: :will_save_change_to_csp_namespace_id?

    after_commit :trigger_security_policies_updates, if: :saved_change_to_csp_namespace_id?

    def self.in_organization(organization)
      safe_find_or_create_by(organization: organization) # rubocop:disable Performance/ActiveRecordSubtransactionMethods -- only uses a subtransaction if creating a record, which should only happen once per organization
    end

    def csp_enabled?
      return false if GitlabSubscriptions::SubscriptionHelper.gitlab_com_subscription?

      csp_namespace_id.present?
    end

    def csp_namespace_locked?
      csp_namespace_locked_until&.future? || false
    end

    private

    def validate_csp_is_group
      return if csp_namespace_id.blank?
      return if csp_namespace&.group_namespace?

      errors.add(:csp_namespace, 'must be a group')
    end

    def assigning_csp_namespace?
      will_save_change_to_csp_namespace_id? && csp_namespace_id.present?
    end

    # A CSP namespace from another organization must never be linkable, or a group in one
    # organization would have its policies and compliance frameworks centrally managed by an
    # unrelated organization.
    def validate_csp_namespace_organization
      return if csp_namespace.blank? || csp_namespace.organization_id == organization_id

      errors.add(:csp_namespace, _('must belong to the same organization'))
    end

    def validate_csp_namespace_unlocked
      return unless csp_namespace_locked?

      errors.add(
        :csp_namespace_id,
        format(
          _("locked until %{timestamp}"),
          timestamp: csp_namespace_locked_until.strftime("%H:%M UTC")
        )
      )
    end

    def set_csp_namespace_lock
      self.csp_namespace_locked_until = CSP_NAMESPACE_LOCK_DURATION.from_now
    end

    def trigger_security_policies_updates
      previous_csp_id = csp_namespace_id_previously_was
      old_configuration = Security::OrchestrationPolicyConfiguration
                            .find_by(namespace_id: previous_csp_id)

      # Recreate the configuration for the previous group to unlink it from all projects and link it to its hierarchy
      ::Security::RecreateOrchestrationConfigurationWorker.perform_async(old_configuration.id) if old_configuration

      ComplianceManagement::ProjectSettingsDestroyWorker.perform_async(previous_csp_id) if previous_csp_id

      new_configuration = csp_namespace&.security_orchestration_policy_configuration
      return unless new_configuration

      # Force resync of the policies for all projects for the new CSP configuration
      Security::SyncScanPoliciesWorker.perform_async(
        new_configuration.id,
        Security::SecurityOrchestrationPolicies::SyncReason.to_params(:force_resync)
      )
    end
  end
end
