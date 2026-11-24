# frozen_string_literal: true

module RemoteDevelopment
  class OrganizationClusterAgentsFinder
    # @param [GraphQL::Schema::Object] organization
    # @param [Symbol] filter
    # @param [User] user
    # @return [ActiveRecord::Relation]
    def self.execute(organization:, filter:, user:)
      return Clusters::Agent.none unless organization &&
        Ability.allowed?(user, :read_organization_cluster_agent_mapping, organization)

      fetch_agents(filter: filter, organization: organization).ordered_by_name
    end

    # @param [RemoteDevelopment::Organization] organization
    # @param [Symbol] filter
    # @return [ActiveRecord::Relation]
    def self.fetch_agents(organization:, filter:)
      case filter
      when :all
        # Returns all agents that have remote development enabled
        Clusters::Agent.for_organizations([organization.id]).with_remote_development_enabled
      when :directly_mapped
        organization.mapped_agents.with_remote_development_enabled
      else
        raise "Unsupported value for filter: #{filter}"
      end
    end
    private_class_method :fetch_agents
  end
end
