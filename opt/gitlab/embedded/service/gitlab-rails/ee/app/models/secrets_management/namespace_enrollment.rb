# frozen_string_literal: true

module SecretsManagement
  class NamespaceEnrollment < ApplicationRecord
    self.table_name = 'secrets_manager_namespace_enrollments'

    belongs_to :namespace, optional: false

    scope :for_namespace, ->(namespace) { where(namespace_id: namespace.id) }
    scope :enabled, -> { where(disabled_at: nil) }
    scope :disabled, -> { where.not(disabled_at: nil) }
    scope :with_add_on_requested, -> { where.not(add_on_requested_at: nil) }

    def self.enrolled?(namespace)
      for_namespace(namespace.root_ancestor).enabled.exists?
    end

    # Add-on intent: the namespace explicitly enabled paid Secrets Manager
    # without a trial. Distinct from plain enrollment, which the trial chain
    # and beta opt-in also create. Not scoped to enabled: an opt-out pauses
    # the add-on, so the state stays paid while disabled.
    def self.add_on_requested?(namespace)
      for_namespace(namespace.root_ancestor).with_add_on_requested.exists?
    end

    def self.beta_enrolled?(namespace)
      for_namespace(namespace.root_ancestor).enabled.where(beta: true).exists?
    end

    # Enrollment is tri-state: no record means never enrolled, a record with
    # `disabled_at` means the owner explicitly turned Secrets Manager off.
    # Only the explicit opt-out revokes the paid-experience implicit grant.
    def self.opted_out?(namespace)
      for_namespace(namespace.root_ancestor).disabled.exists?
    end

    # Shared base of the group enrollment and trial gates.
    def self.licensed_saas_root_group?(namespace)
      return false unless namespace.is_a?(Group)
      return false unless namespace.root?
      return false unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      namespace.licensed_feature_available?(:native_secrets_management)
    end

    def self.enrollment_allowed?(namespace)
      licensed_saas_root_group?(namespace)
    end

    def self.find_by_namespace_id(namespace_id)
      find_by(namespace_id: namespace_id)
    end

    def enabled?
      disabled_at.nil?
    end
  end
end
