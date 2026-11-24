# frozen_string_literal: true

module Security
  class PolicyProjectLink < ApplicationRecord
    self.table_name = 'security_policy_project_links'

    belongs_to :project
    belongs_to :security_policy, class_name: 'Security::Policy', inverse_of: :security_policy_project_links

    validates :security_policy, uniqueness: { scope: :project_id }

    scope :for_project, ->(project) { where(project: project) }

    def self.linked_project_counts(policy_ids)
      counts = where(security_policy_id: policy_ids).group(:security_policy_id).count
      policy_ids.index_with { |id| counts.fetch(id, 0) }
    end
  end
end
