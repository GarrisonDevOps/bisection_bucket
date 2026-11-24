# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      class MainComponentUpdater
        include CreateConstants
        include Files
        include RemoteDevelopmentConstants

        # @param [Hash] context
        # @return [Hash]
        def self.update(context)
          context => {
            processed_devfile: {
              components: Array => components
            },
            tools_dir: String => tools_dir,
            vscode_extension_marketplace_metadata: Hash => vscode_extension_marketplace_metadata
          }

          # NOTE: We will always have exactly one main_component found, because we have already
          #       validated this in devfile processing
          main_component = components.find do |component|
            # NOTE: We can't use pattern matching here, because constants can't be used in pattern matching.
            #       Otherwise, we could do this all in a single pattern match.
            component.dig(:attributes, MAIN_COMPONENT_INDICATOR_ATTRIBUTE.to_sym)
          end

          main_component_container = main_component.fetch(:container)

          update_env_vars(
            main_component_container: main_component_container,
            tools_dir: tools_dir,
            editor_port: WORKSPACE_EDITOR_PORT,
            ssh_port: WORKSPACE_SSH_PORT,
            enable_marketplace: vscode_extension_marketplace_metadata.fetch(:enabled)
          )

          update_endpoints(
            main_component_container: main_component_container,
            editor_port: WORKSPACE_EDITOR_PORT,
            ssh_port: WORKSPACE_SSH_PORT
          )

          context
        end

        # @param [Hash] main_component_container
        # @param [String] tools_dir
        # @param [Integer] editor_port
        # @param [Integer] ssh_port
        # @param [Boolean] enable_marketplace
        # @return [void]
        def self.update_env_vars(main_component_container:, tools_dir:, editor_port:, ssh_port:, enable_marketplace:)
          (main_component_container[:env] ||= []).append(
            {
              # NOTE: Only "TOOLS_DIR" env var is extracted to a constant, because it is the only one referenced
              #       in multiple different classes.
              name: TOOLS_DIR_ENV_VAR,
              value: tools_dir
            },
            {
              name: "GL_VSCODE_LOG_LEVEL",
              value: "info"
            },
            {
              name: "GL_VSCODE_PORT",
              value: editor_port.to_s
            },
            {
              name: "GL_SSH_PORT",
              value: ssh_port.to_s
            },
            {
              name: "GL_VSCODE_ENABLE_MARKETPLACE",
              value: enable_marketplace.to_s
            }
          )

          nil
        end

        # @param [Hash] main_component_container
        # @param [Integer] editor_port
        # @param [Integer] ssh_port
        # @return [void]
        def self.update_endpoints(main_component_container:, editor_port:, ssh_port:)
          (main_component_container[:endpoints] ||= []).append(
            {
              name: "editor-server",
              targetPort: editor_port,
              exposure: "public",
              secure: true,
              protocol: "https"
            },
            {
              name: "ssh-server",
              targetPort: ssh_port,
              exposure: "internal",
              secure: true
            }
          )

          nil
        end

        private_class_method :update_env_vars, :update_endpoints
      end
    end
  end
end
