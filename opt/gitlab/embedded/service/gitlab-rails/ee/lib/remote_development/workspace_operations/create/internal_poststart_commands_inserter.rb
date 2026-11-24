# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      class InternalPoststartCommandsInserter
        include CreateConstants
        include WorkspaceOperationsConstants
        include Files
        include RemoteDevelopmentConstants

        # @param [Hash] context
        # @return [Hash]
        def self.insert(context)
          # TODO: When user-defined postStart commands are supported, add validation in previous devfile validation
          #       steps of the ".../workspace_operations/create" ROP chain.
          #       See: https://gitlab.com/gitlab-org/gitlab/-/issues/505988

          context => {
            processed_devfile: {
              components: Array => components,
              commands: Array => commands,
              events: {
                postStart: Array => poststart_events
              }
            },
            params: {
              agent: agent,
              project: project,
              project_ref: String => project_ref,
            },
            volume_mounts: {
              data_volume: { path: String => volume_path }
            },
          }

          # NOTE: We will always have exactly one main_component found, because we have already
          #       validated this in devfile processing
          main_component = components.find do |component|
            # NOTE: We can't use pattern matching here, because constants can't be used in pattern matching.
            #       Otherwise, we could do this all in a single pattern match.
            component.dig(:attributes, MAIN_COMPONENT_INDICATOR_ATTRIBUTE.to_sym)
          end

          main_component => { name: String => main_component_name }

          if start_agentw?(agent)
            # Add the start_agentw event
            start_agentw_command_id = "gl-start-agentw-command"
            commands << {
              id: start_agentw_command_id,
              exec: {
                commandLine: INTERNAL_POSTSTART_COMMAND_START_AGENTW_SCRIPT,
                component: main_component_name,
                label: INTERNAL_BLOCKING_COMMAND_LABEL,
                workingDir: WORKSPACE_DATA_VOLUME_PATH
              }
            }
          end

          project_cloning_successful_file = "#{volume_path}/#{PROJECT_CLONING_SUCCESSFUL_FILE_NAME}"
          clone_dir = "#{volume_path}/#{project.path}"
          project_url = project.http_url_to_repo

          clone_depth_option = CLONE_DEPTH_OPTION

          # Add the clone_project event
          clone_project_command_id = "gl-clone-project-command"
          # SECURITY REVIEWED: Shell interpolation using format() with escaped variables
          # project_url (user-controlled, escaped), project_ref (user-controlled, escaped)
          # clone_dir (system-controlled, escaped), project_cloning_successful_file (system-controlled, escaped)
          # clone_depth_option (system-controlled, safe constant)
          # Issue: https://gitlab.com/gitlab-org/gitlab/-/issues/547719
          clone_project_script =
            format(
              INTERNAL_POSTSTART_COMMAND_CLONE_PROJECT_SCRIPT,
              project_cloning_successful_file: Shellwords.shellescape(project_cloning_successful_file),
              clone_dir: Shellwords.shellescape(clone_dir),
              project_ref: Shellwords.shellescape(project_ref),
              project_url: Shellwords.shellescape(project_url),
              clone_depth_option: clone_depth_option
            )

          commands << {
            id: clone_project_command_id,
            exec: {
              commandLine: clone_project_script,
              component: main_component_name,
              label: INTERNAL_BLOCKING_COMMAND_LABEL,
              workingDir: WORKSPACE_DATA_VOLUME_PATH
            }
          }

          # Add the clone_unshallow event
          clone_unshallow_command_id = "gl-clone-unshallow-command"
          # SECURITY REVIEWED: Shell interpolation using format() with escaped variables
          # project_cloning_successful_file (system-controlled, escaped), clone_dir (system-controlled, escaped)
          # Issue: https://gitlab.com/gitlab-org/gitlab/-/issues/547719
          clone_unshallow_script =
            format(
              INTERNAL_POSTSTART_COMMAND_CLONE_UNSHALLOW_SCRIPT,
              project_cloning_successful_file: Shellwords.shellescape(project_cloning_successful_file),
              clone_dir: Shellwords.shellescape(clone_dir),
              main_component_name: Shellwords.shellescape(main_component_name)
            )

          commands << {
            id: clone_unshallow_command_id,
            exec: {
              commandLine: clone_unshallow_script,
              component: main_component_name,
              label: INTERNAL_BLOCKING_COMMAND_LABEL,
              workingDir: WORKSPACE_DATA_VOLUME_PATH
            }
          }

          # Add the start_sshd event
          start_sshd_command_id = "gl-start-sshd-command"
          start_sshd_script =
            format(
              INTERNAL_POSTSTART_COMMAND_START_SSHD_SCRIPT,
              main_component_name: Shellwords.shellescape(main_component_name)
            )
          commands << {
            id: start_sshd_command_id,
            exec: {
              commandLine: start_sshd_script,
              component: main_component_name,
              label: INTERNAL_BLOCKING_COMMAND_LABEL,
              workingDir: WORKSPACE_DATA_VOLUME_PATH
            }
          }

          # Add the start_vscode event
          start_vscode_command_id = "gl-init-tools-command"
          start_vscode_script =
            format(
              INTERNAL_POSTSTART_COMMAND_START_VSCODE_SCRIPT,
              main_component_name: Shellwords.shellescape(main_component_name)
            )
          commands << {
            id: start_vscode_command_id,
            exec: {
              commandLine: start_vscode_script,
              component: main_component_name,
              label: INTERNAL_BLOCKING_COMMAND_LABEL,
              workingDir: WORKSPACE_DATA_VOLUME_PATH
            }
          }

          # Add the sleep_until_container_is_running event
          sleep_until_container_is_running_command_id = "gl-sleep-until-container-is-running-command"
          # SECURITY REVIEWED: Shell interpolation using format() with system-controlled constant
          # workspace_reconciled_actual_state_file_path (system-controlled constant)
          # Issue: https://gitlab.com/gitlab-org/gitlab/-/issues/547719
          sleep_until_container_is_running_script =
            format(
              INTERNAL_POSTSTART_COMMAND_SLEEP_UNTIL_WORKSPACE_IS_RUNNING_SCRIPT,
              workspace_reconciled_actual_state_file_path: WORKSPACE_RECONCILED_ACTUAL_STATE_FILE_PATH
            )

          commands << {
            id: sleep_until_container_is_running_command_id,
            exec: {
              commandLine: sleep_until_container_is_running_script,
              component: main_component_name,
              label: INTERNAL_COMMAND_LABEL,
              workingDir: WORKSPACE_DATA_VOLUME_PATH
            }
          }

          commands_to_prepend = [
            clone_project_command_id,
            clone_unshallow_command_id,
            start_sshd_command_id,
            start_vscode_command_id,
            sleep_until_container_is_running_command_id
          ]

          # Insert the start agentw command at the beginning, if the appropriate values are set.
          commands_to_prepend.insert(0, start_agentw_command_id) if start_agentw?(agent)

          # Prepend internal commands so they are executed before any user-defined poststart events.
          poststart_events.prepend(*commands_to_prepend)

          context
        end

        # @param [Clusters::Agent] agent
        # @return [TrueClass, FalseClass]
        def self.start_agentw?(agent)
          gitlab_workspaces_proxy_http_enabled =
            agent.unversioned_latest_workspaces_agent_config.gitlab_workspaces_proxy_http_enabled
          WorkspaceOperations::WorkspaceUrlHelper.common_workspace_host_suffix?(gitlab_workspaces_proxy_http_enabled)
        end

        private_class_method :start_agentw?
      end
    end
  end
end
