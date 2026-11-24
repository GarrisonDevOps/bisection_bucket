# frozen_string_literal: true

module Types
  module RemoteDevelopment
    class NamespaceClusterAgentFilterEnum < BaseEnum
      graphql_name 'NamespaceClusterAgentFilter'
      description 'Possible filter types for remote development cluster agents in a namespace'

      value 'AVAILABLE',
        description: "Cluster agents in the namespace that can be used for hosting workspaces.", value: 'AVAILABLE'

      value 'DIRECTLY_MAPPED',
        description: "Cluster agents that are directly mapped to the given namespace.", value: 'DIRECTLY_MAPPED'

      value 'UNMAPPED',
        description: "Cluster agents within a namespace that are not directly mapped to it.", value: 'UNMAPPED'

      value 'ALL',
        description: "All cluster agents in the namespace that can be used for hosting worksapces.", value: 'ALL'
    end
  end
end
