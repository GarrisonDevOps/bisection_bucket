# frozen_string_literal: true

module Security
  class PipelineExecutionPolicyConfigLink < ApplicationRecord
    self.table_name = 'security_pipeline_execution_policy_config_links'

    belongs_to :project
    belongs_to :security_policy, class_name: 'Security::Policy',
      inverse_of: :security_pipeline_execution_policy_config_link

    validates :security_policy, uniqueness: { scope: :project_id }
    validate :same_organization

    scope :for_project, ->(project) { where(project: project) }
    scope :including_policies, -> do
      includes(security_policy: { security_orchestration_policy_configuration: :security_policy_management_project })
    end

    private

    def same_organization
      return unless project && security_policy&.source
      return if project.organization_id == security_policy.source.organization_id

      errors.add(:project, 'must belong to the same organization as the policy')
    end
  end
end
