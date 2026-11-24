# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      module DesiredConfig
        class ScriptsVolumeInserter
          include CreateConstants
          extend PoststartCommandsHelper

          # @param [String] configmap_name
          # @param [Array<Hash>] containers
          # @param [Array<Hash>] volumes
          # @param [Array<Hash>] devfile_commands
          # @param [Hash] devfile_events
          # @param [Hash] processed_devfile
          # @return [void]
          def self.insert(
            configmap_name:,
            containers:,
            volumes:,
            devfile_commands:,
            devfile_events:,
            processed_devfile:
          )
            poststart_commands = extract_poststart_commands(
              devfile_commands: devfile_commands,
              devfile_events: devfile_events
            )

            configmap_source = { configMap: { name: configmap_name } }

            if internal_blocking_command_label_present?(poststart_commands: poststart_commands)
              configmap_items = build_poststart_script_configmap_items(
                poststart_commands: poststart_commands,
                processed_devfile: processed_devfile
              )
              configmap_source[:configMap][:items] = configmap_items
            end

            volume =
              {
                name: WORKSPACE_SCRIPTS_VOLUME_NAME,
                projected: {
                  defaultMode: WORKSPACE_SCRIPTS_VOLUME_DEFAULT_MODE,
                  sources: [configmap_source]
                }
              }
            volume_mount =
              {
                name: WORKSPACE_SCRIPTS_VOLUME_NAME,
                mountPath: WORKSPACE_SCRIPTS_VOLUME_PATH
              }

            volumes << volume

            containers.each do |container|
              container.fetch(:volumeMounts) << volume_mount
            end

            nil
          end

          # @param [Array<Hash>] poststart_commands
          # @param [Hash] processed_devfile
          # @return [Array<Hash>]
          def self.build_poststart_script_configmap_items(poststart_commands:, processed_devfile:)
            containers_with_devfile_poststart_commands = get_container_names_with_poststart_commands(
              poststart_commands: poststart_commands
            )

            main_component_name = extract_main_component_name(
              processed_devfile: processed_devfile
            )

            configmap_items = poststart_commands.map do |cmd|
              {
                key: cmd[:id].to_s,
                path: "#{cmd.dig(:exec, :component)}/#{cmd[:id]}"
              }
            end

            configmap_items << {
              key: "#{main_component_name}-#{RUN_INTERNAL_BLOCKING_POSTSTART_COMMANDS_SCRIPT_NAME}",
              path: "#{main_component_name}/#{RUN_INTERNAL_BLOCKING_POSTSTART_COMMANDS_SCRIPT_NAME}"
            }

            containers_with_devfile_poststart_commands.each do |container_name|
              configmap_items << {
                key: "#{container_name}-#{RUN_NON_BLOCKING_POSTSTART_COMMANDS_SCRIPT_NAME}",
                path: "#{container_name}/#{RUN_NON_BLOCKING_POSTSTART_COMMANDS_SCRIPT_NAME}"
              }
            end

            configmap_items
          end

          private_class_method :build_poststart_script_configmap_items
        end
      end
    end
  end
end
