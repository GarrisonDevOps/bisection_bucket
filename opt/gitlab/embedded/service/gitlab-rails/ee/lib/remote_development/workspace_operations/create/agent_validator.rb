# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      class AgentValidator
        include Messages

        # @param [Hash] context
        # @return [Gitlab::Fp::Result]
        def self.validate(context)
          context => {
            params: {
              agent: Clusters::Agent => agent,
              project: Project => project
            }
          }

          relevant_org_mappings =
            ::RemoteDevelopment::OrganizationClusterAgentMapping
              .for_organizations([project.organization.id])
              .for_agents([agent.id])

          return Gitlab::Fp::Result.ok(context) if relevant_org_mappings.present?

          relevant_namespace_mappings =
            ::RemoteDevelopment::NamespaceClusterAgentMapping
              .for_namespaces(project.project_namespace.traversal_ids)
              .for_agents([agent.id])

          unless relevant_namespace_mappings.present?
            return Gitlab::Fp::Result.err(
              WorkspaceCreateParamsValidationFailed.new(
                details: "Cannot use agent '#{agent.name}' as an organization mapped agent, the provided agent " \
                  "is not mapped in organization '#{project.organization.name}'. It also cannot be used as a " \
                  "namespace mapped agent, it is not mapped to an ancestor namespace of the workspaces' project.",
                context: context
              )
            )
          end

          valid_relevant_namespace_mappings =
            ::RemoteDevelopment::NamespaceClusterAgentMappingOperations::Validations
              .filter_valid_namespace_cluster_agent_mappings(
                namespace_cluster_agent_mappings: relevant_namespace_mappings.to_a
              )

          unless valid_relevant_namespace_mappings.present?
            return Gitlab::Fp::Result.err(
              WorkspaceCreateParamsValidationFailed.new(
                details: "Cannot use agent '#{agent.name}' as an organization mapped agent, the provided agent " \
                  "is not mapped in organization '#{project.organization.name}'. It also cannot be used as a " \
                  "namespace mapped agent, #{relevant_namespace_mappings.size} mapping(s) exist between the " \
                  "provided agent and the ancestor namespaces of the workspaces' project, but the agent does not " \
                  "reside within the hierarchy of any of the mapped ancestor namespaces.",
                context: context
              )
            )
          end

          Gitlab::Fp::Result.ok(context)
        end
      end
    end
  end
end
