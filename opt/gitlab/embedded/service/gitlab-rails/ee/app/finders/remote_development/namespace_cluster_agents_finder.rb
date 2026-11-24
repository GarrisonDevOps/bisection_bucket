# frozen_string_literal: true

module RemoteDevelopment
  class NamespaceClusterAgentsFinder
    # @param [GraphQL::Schema::Object] namespace
    # @param [Symbol] filter
    # @param [User] user
    # @return [ActiveRecord::Relation]
    def self.execute(namespace:, filter:, user:)
      agents = fetch_agents(namespace: namespace, filter: filter, user: user)

      agents.ordered_by_name
    end

    # @param [GraphQL::Schema::Object] namespace
    # @param [Symbol] filter
    # @param [User] user
    # @return [ActiveRecord::Relation]
    def self.fetch_agents(namespace:, filter:, user:)
      case filter
      when :all
        return Clusters::Agent.none unless user_can_read_namespace_agent_mappings?(user: user, namespace: namespace)

        # Returns all agents with remote development enabled
        namespace.cluster_agents.with_remote_development_enabled
      when :unmapped
        return Clusters::Agent.none unless user_can_read_namespace_agent_mappings?(user: user, namespace: namespace)

        # noinspection RailsParamDefResolve -- A symbol is a valid argument for 'select'
        existing_mapped_agents =
          NamespaceClusterAgentMapping
            .for_namespaces([namespace.id])
            .select(:cluster_agent_id)

        # NOTE: cluster_agents is only defined for group namespace but that is ok as only group namespaces
        # are supported in the current iteration. However, this method will need to refactored/defined within the
        # Namespace if/when this finder is expected to support mappings for user/project namespaces
        # Issue: https://gitlab.com/gitlab-org/gitlab/-/issues/417894
        namespace.cluster_agents.id_not_in(existing_mapped_agents)

      when :directly_mapped
        return Clusters::Agent.none unless user_can_read_namespace_agent_mappings?(user: user, namespace: namespace)

        relevant_mappings = NamespaceClusterAgentMapping.for_namespaces([namespace.id])
        relevant_mappings =
          NamespaceClusterAgentMappingOperations::Validations.filter_valid_namespace_cluster_agent_mappings(
            namespace_cluster_agent_mappings: relevant_mappings.to_a
          )

        Clusters::Agent.id_in(relevant_mappings.map(&:cluster_agent_id))
      when :available
        relevant_mappings = NamespaceClusterAgentMapping.for_namespaces(namespace.traversal_ids)
        relevant_mappings =
          NamespaceClusterAgentMappingOperations::Validations.filter_valid_namespace_cluster_agent_mappings(
            namespace_cluster_agent_mappings: relevant_mappings.to_a
          )

        Clusters::Agent.id_in(relevant_mappings.map(&:cluster_agent_id)).with_remote_development_enabled
      else
        raise "Unsupported value for filter: #{filter}"
      end
    end

    # @param [GraphQL::Schema::Object] namespace
    # @param [User] user
    # @return [Boolean]
    def self.user_can_read_namespace_agent_mappings?(namespace:, user:)
      Ability.allowed?(user, :read_namespace_cluster_agent_mapping, namespace)
    end
  end
end
