# frozen_string_literal: true

module RemoteDevelopment
  module NamespaceClusterAgentMappingOperations
    class Validations
      # The function checks and filters clusters agents that reside within a namespace. All other
      # agents are excluded from the response. A cluster agent is said to reside within a namespace
      # if the namespace id is present in the traversal ids of the project bound to the cluster agent
      #
      # @param [Array<NamespaceClusterAgentMapping>] namespace_cluster_agent_mappings
      # @return [Array<RemoteDevelopment::NamespaceClusterAgentMapping>]
      def self.filter_valid_namespace_cluster_agent_mappings(namespace_cluster_agent_mappings:)
        agent_ids = namespace_cluster_agent_mappings.map(&:cluster_agent_id)
        traversal_ids_for_agents = traversal_ids_for_cluster_agents(cluster_agent_ids: agent_ids)
        namespace_cluster_agent_mappings.filter do |mapping|
          traversal_ids_for_agents.fetch(mapping.cluster_agent_id, []).include?(mapping.namespace_id)
        end
      end

      # @param [Array<Integer>] cluster_agent_ids
      # @return [Hash]
      def self.traversal_ids_for_cluster_agents(cluster_agent_ids:)
        agents_by_id = Clusters::Agent.id_in(cluster_agent_ids).index_by(&:id)

        projects_by_id = Project.id_in(agents_by_id.values.map(&:project_id)).index_by(&:id)

        project_namespaces_by_id =
          Namespaces::ProjectNamespace
            .id_in(projects_by_id.values.map(&:project_namespace_id))
            .index_by(&:id)

        cluster_agent_ids.each_with_object({}) do |cluster_agent_id, hash|
          next unless agents_by_id.has_key?(cluster_agent_id)

          agent = agents_by_id[cluster_agent_id]

          # projects_by_id must contain agent.project_id as "agents" table has a ON CASCADE DELETE constraint with
          # respect to the "projects" table. As such, if an agent can be retrieved from the database,
          # so should its project
          project = projects_by_id[agent.project_id]

          # project_namespaces_by_id must contain project.project_namespace_id as "projects" table has a
          # ON CASCADE DELETE constraint with respect to the projects table. As such, if a project can be retrieved
          # from the database, so should its project_namespace
          # noinspection RubyResolve - https://handbook.gitlab.com/handbook/tools-and-tips/editors-and-ides/jetbrains-ides/tracked-jetbrains-issues/#ruby-31542
          project_namespace = project_namespaces_by_id[project.project_namespace_id]

          hash[cluster_agent_id] = project_namespace.traversal_ids
        end
      end

      private_class_method :traversal_ids_for_cluster_agents
    end
  end
end
