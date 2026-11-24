# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    class SecurityPolicy < ApplicationRecord
      self.table_name = 'compliance_framework_security_policies'

      belongs_to :policy_configuration, class_name: 'Security::OrchestrationPolicyConfiguration'
      belongs_to :framework, class_name: 'ComplianceManagement::Framework'
      belongs_to :security_policy, class_name: 'Security::Policy', optional: true
      belongs_to :namespace, optional: true
      belongs_to :project, optional: true

      validates :framework, uniqueness: { scope: [:policy_configuration_id, :policy_index] }, if: -> {
        security_policy_id.blank?
      }
      validates :framework, uniqueness: { scope: :security_policy_id }, if: -> { security_policy_id.present? }

      scope :for_framework, ->(framework) { where(framework: framework) }
      scope :for_security_policy, ->(security_policy) { where(security_policy: security_policy) }

      has_many :security_policy_requirements,
        class_name: 'ComplianceManagement::ComplianceFramework::SecurityPolicyRequirement',
        foreign_key: :compliance_framework_security_policy_id,
        inverse_of: :compliance_framework_security_policy

      has_many :compliance_requirements,
        through: :security_policy_requirements,
        inverse_of: :compliance_framework_security_policies

      class << self
        def delete_for_security_policy(security_policy)
          for_security_policy(security_policy).each_batch(order_hint: :updated_at) do |batch|
            batch.delete_all
          end
        end

        def relink(security_policy, framework_policy_attrs)
          transaction do
            delete_for_security_policy(security_policy)

            framework_policy_attrs = same_organization_framework_attrs(security_policy, framework_policy_attrs)

            if framework_policy_attrs.any?
              insert_all(framework_policy_attrs, unique_by: [:security_policy_id, :framework_id])
            end
          end
        end

        private

        # insert_all bypasses model validations, so a framework from another organization must be
        # filtered out here rather than relying solely on callers to pre-scope framework_policy_attrs.
        def same_organization_framework_attrs(security_policy, framework_policy_attrs)
          return framework_policy_attrs if framework_policy_attrs.empty?

          organization = security_policy.source.organization
          attrs_by_framework_id = framework_policy_attrs.group_by { |attrs| attrs[:framework_id] }

          same_organization_framework_ids =
            ComplianceManagement::Framework.ids_in_organization(attrs_by_framework_id.keys, organization)

          same_organization_framework_ids.flat_map { |id| attrs_by_framework_id[id] }
        end
      end
    end
  end
end
