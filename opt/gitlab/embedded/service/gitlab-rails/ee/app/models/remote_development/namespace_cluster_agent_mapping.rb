# frozen_string_literal: true

module RemoteDevelopment
  # model
  class NamespaceClusterAgentMapping < ApplicationRecord
    belongs_to :namespace, inverse_of: :namespace_cluster_agent_mappings
    belongs_to :user,
      class_name: 'User',
      foreign_key: 'creator_id',
      inverse_of: :created_namespace_cluster_agent_mappings
    belongs_to :agent,
      class_name: 'Clusters::Agent',
      foreign_key: 'cluster_agent_id',
      inverse_of: :namespace_cluster_agent_mappings

    validates :namespace, presence: true
    validates :agent, presence: true
    validates :user, presence: true

    scope :for_namespaces, ->(namespace_ids) { where(namespace_id: namespace_ids) }
    scope :for_agents, ->(agent_ids) { where(cluster_agent_id: agent_ids) }
  end
end
