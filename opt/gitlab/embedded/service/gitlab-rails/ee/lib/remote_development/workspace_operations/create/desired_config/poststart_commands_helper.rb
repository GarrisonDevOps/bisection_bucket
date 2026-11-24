# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      module DesiredConfig
        module PoststartCommandsHelper
          include RemoteDevelopmentConstants
          include WorkspaceOperationsConstants

          # @param [Array<Hash>] devfile_commands
          # @param [Hash] devfile_events
          # @return [Array<Hash>]
          def extract_poststart_commands(devfile_commands:, devfile_events:)
            return [] unless devfile_events[:postStart].present?

            poststart_command_ids = devfile_events.fetch(:postStart)

            poststart_command_ids.filter_map do |id|
              devfile_commands.find { |cmd| cmd[:id] == id }
            end
          end

          # @param [Hash] processed_devfile
          # @return [String]
          def extract_main_component_name(processed_devfile:)
            components = processed_devfile.fetch(:components)

            main_component = components.find do |component|
              component.dig(:attributes, MAIN_COMPONENT_INDICATOR_ATTRIBUTE.to_sym)
            end

            main_component.fetch(:name)
          end

          # @param [Array<Hash>] poststart_commands
          # @return [Array<String>]
          def get_container_names_with_poststart_commands(poststart_commands:)
            poststart_commands.map { |cmd| cmd[:exec][:component] }.uniq
          end

          # @param [Array<Hash>] poststart_commands
          # @return [Boolean]
          def internal_blocking_command_label_present?(poststart_commands:)
            poststart_commands.any? do |command|
              command.dig(:exec, :label) == INTERNAL_BLOCKING_COMMAND_LABEL
            end
          end

          # @param [Array<Hash>] poststart_commands
          # @return [Array<Array<Hash>, Array<Hash>>]
          def partition_poststart_commands(poststart_commands:)
            poststart_commands.partition do |poststart_cmd|
              poststart_cmd&.dig(:exec, :label) == INTERNAL_BLOCKING_COMMAND_LABEL
            end
          end

          # @param [Array<Hash>] non_blocking_commands
          # @return [Hash]
          def group_commands_by_component(non_blocking_commands:)
            non_blocking_commands.group_by do |cmd|
              cmd[:exec][:component]
            end
          end
        end
      end
    end
  end
end
