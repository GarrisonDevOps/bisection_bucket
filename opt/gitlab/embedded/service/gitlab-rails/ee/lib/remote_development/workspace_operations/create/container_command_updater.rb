# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      class ContainerCommandUpdater
        include Files
        include RemoteDevelopmentConstants

        # @param [Hash] context
        # @return [Hash]
        def self.update(context)
          context => {
            processed_devfile: {
              components: Array => components
            }
          }

          components.each do |component|
            attributes = component[:attributes] ||= {}

            # If overrideCommand is not present, set it based on whether it's the main component
            # Defaults to true for the main_component and false for all other components
            unless attributes.key?(:overrideCommand)
              is_main_component = attributes[MAIN_COMPONENT_INDICATOR_ATTRIBUTE.to_sym]
              attributes[:overrideCommand] = is_main_component ? true : false
            end

            override_enabled = component.dig(:attributes, :overrideCommand) == true

            # Skip if overrideCommand is not enabled or component name starts with restricted prefix
            next unless override_enabled

            container = component[:container]
            next unless container

            # This overrides the entrypoint command for the container
            container[:command] = %w[/bin/sh -c]
            container[:args] = [CONTAINER_KEEPALIVE_COMMAND_ARGS]
          end

          context
        end
      end
    end
  end
end
