# frozen_string_literal: true

module RemoteDevelopment
  module NamespaceClusterAgentMappingOperations
    module Delete
      class MappingDeleter
        include Messages

        # @param [Hash] context
        # @return [Gitlab::Fp::Result]
        def self.delete(context)
          context => {
            namespace: Namespace => namespace,
            cluster_agent: Clusters::Agent => cluster_agent
          }

          mapping = NamespaceClusterAgentMapping.for_namespaces([namespace.id])
                                                .for_agents([cluster_agent.id])
                                                .first

          return Gitlab::Fp::Result.err(NamespaceClusterAgentMappingNotFound.new) unless mapping

          delete_count = mapping.delete

          return Gitlab::Fp::Result.err(NamespaceClusterAgentMappingNotFound.new) if delete_count == 0

          Gitlab::Fp::Result.ok(NamespaceClusterAgentMappingDeleteSuccessful.new({
            namespace_cluster_agent_mapping: mapping
          }))
        end
      end
    end
  end
end
