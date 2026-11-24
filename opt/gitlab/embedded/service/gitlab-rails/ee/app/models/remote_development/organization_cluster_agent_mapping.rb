# frozen_string_literal: true

module RemoteDevelopment
  class OrganizationClusterAgentMapping < ApplicationRecord
    belongs_to :organization, class_name: 'Organizations::Organization',
      inverse_of: :organization_cluster_agent_mappings
    belongs_to :user,
      class_name: 'User',
      foreign_key: 'creator_id',
      inverse_of: :created_organization_cluster_agent_mappings
    belongs_to :agent,
      class_name: 'Clusters::Agent',
      foreign_key: 'cluster_agent_id',
      inverse_of: :organization_cluster_agent_mapping

    validates :organization, presence: true
    validates :agent, presence: true
    validates :user, presence: true, on: :create

    scope :for_organizations, ->(organization_ids) { where(organization_id: organization_ids) }
    scope :for_agents, ->(agent_ids) { where(cluster_agent_id: agent_ids) }
  end
end
