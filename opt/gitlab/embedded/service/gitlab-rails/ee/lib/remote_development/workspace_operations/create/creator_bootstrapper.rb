# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      class CreatorBootstrapper
        include CreateConstants

        # @param [Hash] context
        # @return [Hash]
        def self.bootstrap(context)
          # Skip type checking so we can use fast_spec_helper in the unit test spec
          context => {
            params: {
              agent: agent
            }
          }

          workspace_name = WorkspaceNameGenerator.generate
          shared_namespace = agent.unversioned_latest_workspaces_agent_config.shared_namespace

          workspace_namespace =
            # NOTE: Empty string is a "magic value" that indicates default per-workspace namespaces should be used.
            case shared_namespace
            when ""
              # Use a unique namespace, with one workspace per namespace
              "#{NAMESPACE_PREFIX}-#{workspace_name}"
            else
              # Use a shared namespace, with multiple workspaces in the same namespace
              shared_namespace
            end

          context.merge(
            workspace_name: workspace_name,
            workspace_namespace: workspace_namespace
          )
        end
      end
    end
  end
end
