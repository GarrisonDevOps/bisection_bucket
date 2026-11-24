# frozen_string_literal: true

module RemoteDevelopment
  module WorkspacesServerOperations
    module AuthorizeUserAccess
      class WorkspaceFinder
        include Messages
        extend Gitlab::Fp::MessageSupport

        # Find the workspace by name
        # @param [Hash] context
        # @return [Gitlab::Fp::Result]
        def self.find_workspace(context)
          context => {
            workspace_name: String => workspace_name
          }

          workspace = ::RemoteDevelopment::Workspace.find_by_name(workspace_name)

          unless workspace
            return Gitlab::Fp::Result.err(
              WorkspaceAuthorizeUserAccessFailed.new({ status: Status::WORKSPACE_NOT_FOUND })
            )
          end

          # Add the workspace to context
          Gitlab::Fp::Result.ok(
            context.merge(workspace: workspace)
          )
        end
      end
    end
  end
end
