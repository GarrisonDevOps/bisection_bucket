# frozen_string_literal: true

module RemoteDevelopment
  module NamespaceClusterAgentMappingOperations
    module Create
      class ClusterAgentValidator
        include Messages

        # @param [Hash] context
        # @return [Gitlab::Fp::Result]
        def self.validate(context)
          context => {
            namespace: Namespace => namespace,
            cluster_agent: Clusters::Agent => cluster_agent,
          }

          # Verify the agent's project is in the same namespace as the namespace we intend to map it to.
          unless cluster_agent.project.project_namespace.traversal_ids.exclude?(namespace.id)
            return Gitlab::Fp::Result.ok(context)
          end

          Gitlab::Fp::Result.err(NamespaceClusterAgentMappingCreateValidationFailed.new({
            details: "Cluster Agent's project must be nested within the namespace"
          }))
        end
      end
    end
  end
end
