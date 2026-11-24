# frozen_string_literal: true

module Security
  module ScanExecutionPolicies
    class Agents
      def initialize(agents)
        @agents = agents || {}
      end

      def agent_names
        agents.keys
      end

      def namespaces_for_agent(agent_name)
        agent_config = agents[agent_name] || {}
        agent_config[:namespaces] || []
      end

      private

      attr_reader :agents
    end
  end
end
