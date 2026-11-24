# frozen_string_literal: true

module Types
  module RemoteDevelopment
    class OrganizationClusterAgentFilterEnum < BaseEnum
      graphql_name 'OrganizationClusterAgentFilter'
      description 'Possible filter types for remote development cluster agents in an organization'

      value 'DIRECTLY_MAPPED',
        description: "Cluster agents that are directly mapped to the given organization.", value: 'DIRECTLY_MAPPED'

      value 'ALL',
        description: "All cluster agents in the organization that can be used for hosting workspaces.", value: 'ALL'
    end
  end
end
