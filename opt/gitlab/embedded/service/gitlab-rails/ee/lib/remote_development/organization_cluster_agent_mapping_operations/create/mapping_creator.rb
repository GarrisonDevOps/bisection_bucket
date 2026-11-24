# frozen_string_literal: true

module RemoteDevelopment
  module OrganizationClusterAgentMappingOperations
    module Create
      class MappingCreator
        include Messages

        # @param [Hash] context
        # @return [Gitlab::Fp::Result]
        def self.create(context)
          context => {
            organization: Organizations::Organization => organization,
            agent: Clusters::Agent => agent,
            user: User => user
          }

          new_mapping = OrganizationClusterAgentMapping.new(
            cluster_agent_id: agent.id,
            organization_id: organization.id,
            creator_id: user.id
          )

          begin
            new_mapping.save
          rescue ActiveRecord::RecordNotUnique
            return Gitlab::Fp::Result.err(OrganizationClusterAgentMappingAlreadyExists.new)
          end

          if new_mapping.errors.present?
            return Gitlab::Fp::Result.err(
              OrganizationClusterAgentMappingCreateFailed.new({ errors: new_mapping.errors })
            )
          end

          Gitlab::Fp::Result.ok(
            OrganizationClusterAgentMappingCreateSuccessful.new({ organization_cluster_agent_mapping: new_mapping })
          )
        end
      end
    end
  end
end
