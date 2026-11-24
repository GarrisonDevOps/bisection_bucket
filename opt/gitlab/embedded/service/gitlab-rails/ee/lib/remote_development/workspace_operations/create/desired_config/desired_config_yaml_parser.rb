# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      module DesiredConfig
        class DesiredConfigYamlParser
          # @param [Hash] context
          # @return [Hash]
          def self.parse(context)
            context => {
              desired_config_yaml: desired_config_yaml
            }

            desired_config_array = YAML.load_stream(desired_config_yaml).map(&:deep_symbolize_keys)

            context.merge({
              desired_config_array: desired_config_array
            })
          end
        end
      end
    end
  end
end
