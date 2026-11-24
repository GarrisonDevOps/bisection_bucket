# frozen_string_literal: true

module Mutations
  module RemoteDevelopment
    module OrganizationClusterAgentMappingOperations
      class Create < BaseMutation
        graphql_name 'OrganizationCreateClusterAgentMapping'

        include Gitlab::Utils::UsageData

        authorize :create_cluster_agent_mapping
        authorize_granular_token permissions: :create_cluster_agent_mapping, boundary: :instance,
          boundary_type: :instance

        argument :cluster_agent_id,
          ::Types::GlobalIDType[::Clusters::Agent],
          required: true,
          description: 'GlobalID of the cluster agent to be associated with the organization.'

        argument :organization_id,
          ::Types::GlobalIDType[::Organizations::Organization],
          required: true,
          description: 'GlobalID of the organization to be associated with the cluster agent.'

        # @param [Hash] args
        # @return [Hash]
        def resolve(args)
          unless License.feature_available?(:remote_development)
            raise_resource_not_available_error!("'remote_development' licensed feature is not available")
          end

          organization_id = args.delete(:organization_id)
          organization = authorized_find!(id: organization_id)

          agent_id = args.delete(:cluster_agent_id)
          agent = authorized_find!(id: agent_id)

          domain_main_class_args = {
            organization: organization,
            agent: agent,
            user: current_user
          }

          response = ::RemoteDevelopment::CommonService.execute(
            domain_main_class: ::RemoteDevelopment::OrganizationClusterAgentMappingOperations::Create::Main,
            domain_main_class_args: domain_main_class_args
          )

          {
            errors: response.errors
          }
        end
      end
    end
  end
end
