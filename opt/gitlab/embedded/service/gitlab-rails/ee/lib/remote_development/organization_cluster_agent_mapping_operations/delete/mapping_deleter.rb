# frozen_string_literal: true

module RemoteDevelopment
  module OrganizationClusterAgentMappingOperations
    module Delete
      class MappingDeleter
        include Messages

        # @param [Hash] context
        # @return [Gitlab::Fp::Result]
        def self.delete(context)
          context => {
            organization: Organizations::Organization => organization,
            agent: Clusters::Agent => agent
          }

          delete_count = OrganizationClusterAgentMapping.delete_by(
            organization_id: organization.id,
            cluster_agent_id: agent.id
          )

          return Gitlab::Fp::Result.err(OrganizationClusterAgentMappingNotFound.new) if delete_count == 0

          Gitlab::Fp::Result.ok(OrganizationClusterAgentMappingDeleteSuccessful.new({}))
        end
      end
    end
  end
end
