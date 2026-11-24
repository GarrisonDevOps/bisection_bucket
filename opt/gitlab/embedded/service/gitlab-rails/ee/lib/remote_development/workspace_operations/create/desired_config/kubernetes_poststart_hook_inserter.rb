# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      module DesiredConfig
        # NOTE: This class has "Kubernetes" prepended to "Poststart" in the name to make it explicit that it
        #       deals with Kubernetes postStart hooks in the Kubernetes Deployment resource, and that
        #       it is NOT dealing with the postStart events which are found in devfiles.
        class KubernetesPoststartHookInserter
          include Files
          include CreateConstants
          extend PoststartCommandsHelper

          # @param [Array] containers
          # @param [Array<Hash>] devfile_commands
          # @param [Hash] devfile_events
          # @param [Hash] processed_devfile
          # @return [void]
          def self.insert(containers:, devfile_commands:, devfile_events:, processed_devfile:)
            poststart_commands = extract_poststart_commands(
              devfile_commands: devfile_commands,
              devfile_events: devfile_events
            )

            main_component_name = extract_main_component_name(
              processed_devfile: processed_devfile
            )

            internal_blocking_command_label_present = internal_blocking_command_label_present?(
              poststart_commands: poststart_commands
            )

            containers_with_devfile_poststart_commands = get_container_names_with_poststart_commands(
              poststart_commands: poststart_commands
            )

            containers.each do |container|
              container_name = container.fetch(:name)

              container_script_path = "#{WORKSPACE_SCRIPTS_VOLUME_PATH}/#{container_name}/"

              next unless containers_with_devfile_poststart_commands.include?(container_name)

              if internal_blocking_command_label_present
                # SECURITY REVIEWED: Shell interpolation using format() with system-controlled paths
                # run_internal_blocking_poststart_commands_script_file_path (system-controlled path)
                # run_non_blocking_poststart_commands_script_file_path (system-controlled path)
                # Issue: https://gitlab.com/gitlab-org/gitlab/-/issues/547719
                kubernetes_poststart_hook_script =
                  format(
                    KUBERNETES_POSTSTART_HOOK_COMMAND,
                    run_internal_blocking_poststart_commands_script_file_path:
                      container_script_path + RUN_INTERNAL_BLOCKING_POSTSTART_COMMANDS_SCRIPT_NAME,
                    run_non_blocking_poststart_commands_script_file_path:
                      container_script_path + RUN_NON_BLOCKING_POSTSTART_COMMANDS_SCRIPT_NAME,
                    component_name: container_name,
                    main_component_name: main_component_name
                  )
              else
                # SECURITY REVIEWED: Shell interpolation using format() with system-controlled path
                # run_internal_blocking_poststart_commands_script_file_path (system-controlled path)
                # Issue: https://gitlab.com/gitlab-org/gitlab/-/issues/547719
                kubernetes_poststart_hook_script =
                  format(
                    KUBERNETES_LEGACY_POSTSTART_HOOK_COMMAND,
                    run_internal_blocking_poststart_commands_script_file_path:
                      "#{WORKSPACE_SCRIPTS_VOLUME_PATH}/#{LEGACY_RUN_POSTSTART_COMMANDS_SCRIPT_NAME}"
                  )
              end

              container[:lifecycle] = {
                postStart: {
                  exec: {
                    command: ["/bin/sh", "-c", kubernetes_poststart_hook_script]
                  }
                }
              }
            end

            nil
          end
        end
      end
    end
  end
end
