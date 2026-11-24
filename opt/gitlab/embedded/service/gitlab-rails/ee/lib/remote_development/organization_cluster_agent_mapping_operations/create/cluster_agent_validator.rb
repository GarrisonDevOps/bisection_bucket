# frozen_string_literal: true

module RemoteDevelopment
  module OrganizationClusterAgentMappingOperations
    module Create
      class ClusterAgentValidator
        include Messages

        # @param [Hash] context
        # @return [Gitlab::Fp::Result]
        def self.validate(context)
          context => {
            organization: Organizations::Organization => organization,
            agent: Clusters::Agent => agent
          }

          return Gitlab::Fp::Result.ok(context) unless agent.project.organization.id != organization.id

          Gitlab::Fp::Result.err(OrganizationClusterAgentMappingCreateValidationFailed.new({
            details: "Cluster Agent's project must be within the organization"
          }))
        end
      end
    end
  end
end
