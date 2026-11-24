# frozen_string_literal: true

module EE
  # Clusters::AgentsFinder
  #
  # Extends Clusters::AgentsFinder
  #
  # Added arguments:
  #   params:
  #     has_vulnerabilities: boolean
  #
  module Clusters
    module AgentsFinder
      extend ::Gitlab::Utils::Override

      private

      override :filter_clusters

      def filter_clusters(agents)
        agents = super(agents)
        agents = agents.has_vulnerabilities(params[:has_vulnerabilities]) unless params[:has_vulnerabilities].nil?

        # TODO: clusterAgent.hasRemoteDevelopmentAgentConfig GraphQL is deprecated - remove in 17.10 - https://gitlab.com/gitlab-org/gitlab/-/issues/480769
        if !params[:has_workspaces_agent_config].nil? || !params[:has_remote_development_agent_config].nil?
          has_config =
            params[:has_workspaces_agent_config] == true || params[:has_remote_development_agent_config] == true
          case has_config
          when true
            agents = agents.with_workspaces_agent_config
          when false
            agents = agents.without_workspaces_agent_config
          end
        end

        agents = agents.with_remote_development_enabled if params[:has_remote_development_enabled]

        agents
      end
    end
  end
end
