# frozen_string_literal: true

module Mutations
  module RemoteDevelopment
    module NamespaceClusterAgentMappingOperations
      class Create < BaseMutation
        graphql_name 'NamespaceCreateRemoteDevelopmentClusterAgentMapping'

        include Gitlab::Utils::UsageData

        authorize :admin_namespace_cluster_agent_mapping
        authorize_granular_token permissions: :create_cluster_agent_mapping, boundary_argument: :namespace_id,
          boundary_type: :group

        field :namespace_cluster_agent_mapping,
          ::Types::RemoteDevelopment::NamespaceClusterAgentMappingType,
          null: true,
          experiment: { milestone: '17.10' },
          description: 'Created namespace cluster agent mapping.'

        argument :cluster_agent_id,
          ::Types::GlobalIDType[::Clusters::Agent],
          required: true,
          description: 'GlobalID of the cluster agent to be associated with the namespace.'

        argument :namespace_id,
          ::Types::GlobalIDType[::Group],
          required: true,
          description: 'GlobalID of the group to be associated with the cluster agent.'

        # @param [Hash] args
        # @return [Hash]
        def resolve(args)
          unless License.feature_available?(:remote_development)
            raise_resource_not_available_error!("'remote_development' licensed feature is not available")
          end

          # Authorize the user on the Group as the subject for the ability
          namespace_id = args.delete(:namespace_id)
          namespace = authorized_find!(id: namespace_id)

          # Authorize the user on the Agent(which delegates to the Project) as the subject for the ability,
          # this second call is needed as the agent might not be in the same namespace that
          # we previously authorized against.
          cluster_agent_id = args.delete(:cluster_agent_id)
          cluster_agent = authorized_find!(id: cluster_agent_id)

          domain_main_class_args = {
            namespace: namespace,
            cluster_agent: cluster_agent,
            user: current_user
          }

          response = ::RemoteDevelopment::CommonService.execute(
            domain_main_class: ::RemoteDevelopment::NamespaceClusterAgentMappingOperations::Create::Main,
            domain_main_class_args: domain_main_class_args
          )

          response_object = response.success? ? response.payload[:namespace_cluster_agent_mapping] : nil

          {
            namespace_cluster_agent_mapping: response_object,
            errors: response.errors
          }
        end
      end
    end
  end
end
