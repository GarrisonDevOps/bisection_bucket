# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      class ToolsInjectorComponentInserter
        include CreateConstants

        # @param [Hash] context
        # @return [Hash]
        def self.insert(context)
          context => {
            processed_devfile: Hash => processed_devfile,
            tools_dir: String => tools_dir,
            settings: Hash => settings,
          }
          settings => { tools_injector_image: String => image_from_settings }

          # TODO: https://gitlab.com/gitlab-org/gitlab/-/issues/409775 - choose image based on which editor is passed.
          insert_tools_injector_component(
            processed_devfile: processed_devfile,
            tools_dir: tools_dir,
            image: image_from_settings
          )

          context
        end

        # @param [Hash] processed_devfile
        # @param [String] tools_dir
        # @param [String] image
        # @return [void]
        def self.insert_tools_injector_component(processed_devfile:, tools_dir:, image:)
          processed_devfile.fetch(:components) << {
            name: TOOLS_INJECTOR_COMPONENT_NAME,
            container: {
              image: image,
              env: [
                {
                  name: TOOLS_DIR_ENV_VAR,
                  value: tools_dir
                }
              ],
              memoryLimit: "512Mi",
              memoryRequest: "256Mi",
              cpuLimit: "500m",
              cpuRequest: "100m"
            }
          }

          command_id = "#{TOOLS_INJECTOR_COMPONENT_NAME}-command"
          processed_devfile[:commands] << {
            id: command_id,
            apply: {
              component: TOOLS_INJECTOR_COMPONENT_NAME
            }
          }

          processed_devfile.fetch(:events)[:preStart] << command_id

          nil
        end

        private_class_method :insert_tools_injector_component
      end
    end
  end
end
