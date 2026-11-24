# frozen_string_literal: true

module RemoteDevelopment
  module NamespaceClusterAgentMappingOperations
    module Create
      class MappingCreator
        include Messages

        # @param [Hash] context
        # @return [Gitlab::Fp::Result]
        def self.create(context)
          context => {
            namespace: Namespace => namespace,
            cluster_agent: Clusters::Agent => cluster_agent,
            user: User => user
          }

          new_mapping = NamespaceClusterAgentMapping.new(
            cluster_agent_id: cluster_agent.id,
            namespace_id: namespace.id,
            creator_id: user.id
          )

          begin
            new_mapping.save
          rescue ActiveRecord::RecordNotUnique
            return Gitlab::Fp::Result.err(NamespaceClusterAgentMappingAlreadyExists.new)
          end

          if new_mapping.errors.present?
            return Gitlab::Fp::Result.err(NamespaceClusterAgentMappingCreateFailed.new({ errors: new_mapping.errors }))
          end

          Gitlab::Fp::Result.ok(
            NamespaceClusterAgentMappingCreateSuccessful.new({ namespace_cluster_agent_mapping: new_mapping })
          )
        end
      end
    end
  end
end
