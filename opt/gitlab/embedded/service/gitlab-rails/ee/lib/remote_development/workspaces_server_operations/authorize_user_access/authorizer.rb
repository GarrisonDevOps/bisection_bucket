# frozen_string_literal: true

module RemoteDevelopment
  module WorkspacesServerOperations
    module AuthorizeUserAccess
      class Authorizer
        include Messages
        extend Gitlab::Fp::MessageSupport

        # @param [Hash] context
        # @return [Gitlab::Fp::Result]
        def self.authorize(context)
          context => {
            user_id: Integer => user_id,
            workspace: workspace,
            port: String => port
          }

          unless workspace.user_id == user_id
            return Gitlab::Fp::Result.err(
              WorkspaceAuthorizeUserAccessFailed.new({ status: Status::NOT_AUTHORIZED })
            )
          end

          unless port_exposed_for_workspace?(workspace, port)
            return Gitlab::Fp::Result.err(
              WorkspaceAuthorizeUserAccessFailed.new({ status: Status::PORT_NOT_FOUND })
            )
          end

          Gitlab::Fp::Result.ok(
            context.merge(
              response_payload: {
                status: Status::AUTHORIZED,
                info: {
                  port: port,
                  workspace_id: workspace.id
                }
              }
            )
          )
        end

        # @param [RemoteDevelopment::Workspace] workspace
        # @param [String] port
        # @return [Boolean]
        def self.port_exposed_for_workspace?(workspace, port)
          components = YAML.safe_load(workspace.processed_devfile).to_h.deep_symbolize_keys.fetch(:components, [])
          components.each do |component|
            # The endpoints can be available in either container, kubernetes and openshift components of the devfile.
            # We only support container component so far.
            container = component.fetch(:container, {})
            endpoints = container.fetch(:endpoints, [])
            endpoints.each do |endpoint|
              return true if endpoint.fetch(:targetPort, -1).to_s == port
            end
          end

          false
        end

        private_class_method :port_exposed_for_workspace?
      end
    end
  end
end
