# frozen_string_literal: true

module RemoteDevelopment
  module AgentPrerequisitesOperations
    class ResponseBuilder
      # @param [Hash] context
      # @return [Hash]
      def self.build(context)
        # NOTE: We do not type-check here because we want to use the fast_spec_helper in the specs.
        #       We trust that we will get the right object type from the API layer above.
        context => { agent: agent }

        context.merge(
          response_payload: {
            shared_namespace: agent.unversioned_latest_workspaces_agent_config.shared_namespace
          }
        )
      end
    end
  end
end
