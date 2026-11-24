# frozen_string_literal: true

module RemoteDevelopment
  # This module contains constants for all the files (default devfile, shell scripts, script fragments, commands, etc)
  # that are used in the Remote Development domain. They are pulled out to separate files instead of being hardcoded
  # via inline HEREDOC or other means, so that they can have full support for
  # syntax highlighting, refactoring, linting, etc.
  module Files
    # @param [String] path - file path relative to domain logic root (this directory, `ee/lib/remote_development`)
    # @return [String] content of the file
    def self.read_file(path)
      File.read(File.join(__dir__, path))
    end

    # @return [String] content of the file
    def self.default_devfile_yaml
      # When updating DEFAULT_DEVFILE_YAML contents in `default_devfile.yaml`, update the user facing doc as well.
      # https://docs.gitlab.com/ee/user/workspace/#gitlab-default-devfile
      #
      # The container image is pinned by the digest of its multi-platform image index (linux/amd64 and
      # linux/arm64), so the container runtime pulls the variant matching the node. It must be built for the
      # same platforms as WORKSPACE_TOOLS_IMAGE: the injected tools are built for the node's architecture and
      # cannot run in a container image built only for another architecture.
      read_file("settings/default_devfile.yaml")
    end

    # @return [String] content of the file
    def self.git_credential_store_script
      read_file("workspace_operations/create/workspace_variables_git_credential_store.sh")
    end

    # @return [String] content of the file
    def self.kubernetes_legacy_poststart_hook_command
      read_file("workspace_operations/create/desired_config/kubernetes_legacy_poststart_hook_command.sh")
    end

    # @return [String] content of the file
    def self.kubernetes_poststart_hook_command
      read_file("workspace_operations/create/desired_config/kubernetes_poststart_hook_command.sh")
    end

    # @return [String] content of the file
    def self.container_keepalive_command_args
      read_file("workspace_operations/create/container_keepalive_command_args.sh")
    end

    # @return [String] content of the file
    def self.internal_poststart_command_start_agentw_script
      read_file("workspace_operations/create/internal_poststart_command_start_agentw.sh")
    end

    # @return [String] content of the file
    def self.internal_poststart_command_start_vscode_script
      read_file("workspace_operations/create/internal_poststart_command_start_vscode.sh")
    end

    # @return [String] content of the file
    def self.internal_poststart_command_sleep_until_workspace_is_running_script
      read_file("workspace_operations/create/internal_poststart_command_sleep_until_workspace_is_running.sh")
    end

    # @return [String] content of the file
    def self.internal_poststart_command_start_sshd_script
      read_file("workspace_operations/create/internal_poststart_command_start_sshd.sh")
    end

    # @return [String] content of the file
    def self.internal_poststart_command_clone_project_script
      read_file("workspace_operations/create/internal_poststart_command_clone_project.sh")
    end

    # @return [String] content of the file
    def self.internal_poststart_command_clone_unshallow_script
      read_file("workspace_operations/create/internal_poststart_command_clone_unshallow.sh")
    end

    ####################################
    # Please keep this list alphabetized
    ####################################

    # NOTE: We intentionally duplicate these explicit declaration of constants in addition to dynamically redefining
    #       them in `reload_constants!` method below. This is because we want them to be resolve-able in IDEs, and if
    #       we only define them dynamically, they will not be recognized by IDEs.
    DEFAULT_DEVFILE_YAML = default_devfile_yaml
    GIT_CREDENTIAL_STORE_SCRIPT = git_credential_store_script
    INTERNAL_POSTSTART_COMMAND_CLONE_PROJECT_SCRIPT = internal_poststart_command_clone_project_script
    INTERNAL_POSTSTART_COMMAND_CLONE_UNSHALLOW_SCRIPT = internal_poststart_command_clone_unshallow_script
    INTERNAL_POSTSTART_COMMAND_START_AGENTW_SCRIPT = internal_poststart_command_start_agentw_script
    INTERNAL_POSTSTART_COMMAND_START_VSCODE_SCRIPT = internal_poststart_command_start_vscode_script
    INTERNAL_POSTSTART_COMMAND_SLEEP_UNTIL_WORKSPACE_IS_RUNNING_SCRIPT =
      internal_poststart_command_sleep_until_workspace_is_running_script
    INTERNAL_POSTSTART_COMMAND_START_SSHD_SCRIPT = internal_poststart_command_start_sshd_script
    KUBERNETES_LEGACY_POSTSTART_HOOK_COMMAND = kubernetes_legacy_poststart_hook_command
    KUBERNETES_POSTSTART_HOOK_COMMAND = kubernetes_poststart_hook_command
    CONTAINER_KEEPALIVE_COMMAND_ARGS = container_keepalive_command_args

    # @return [Array]
    def self.all_expected_file_constants
      # NOTE: We explicitly keep a duplicate list of the defined constants, to ensure that we keep both the explicit
      #       declarations above and the dynamically defined ones in reload_constants! in sync.
      [
        :DEFAULT_DEVFILE_YAML,
        :GIT_CREDENTIAL_STORE_SCRIPT,
        :INTERNAL_POSTSTART_COMMAND_CLONE_PROJECT_SCRIPT,
        :INTERNAL_POSTSTART_COMMAND_CLONE_UNSHALLOW_SCRIPT,
        :INTERNAL_POSTSTART_COMMAND_START_VSCODE_SCRIPT,
        :INTERNAL_POSTSTART_COMMAND_SLEEP_UNTIL_WORKSPACE_IS_RUNNING_SCRIPT,
        :INTERNAL_POSTSTART_COMMAND_START_SSHD_SCRIPT,
        :KUBERNETES_LEGACY_POSTSTART_HOOK_COMMAND,
        :KUBERNETES_POSTSTART_HOOK_COMMAND,
        :CONTAINER_KEEPALIVE_COMMAND_ARGS
      ]
    end

    # @return [void]
    def self.reload_constants!
      expected_count = 10 # Update this count if you add/remove constants
      raise "File constants count mismatch!" unless all_expected_file_constants.count == expected_count

      all_expected_file_constants.each do |const_name|
        remove_const(const_name) # If you get an exception on this line, update the `all_file_constants` method above
        method_name = const_name.to_s.downcase
        const_set(const_name, public_method(method_name).call)
      end
    end

    private_class_method :all_expected_file_constants, :read_file

    reload_constants!
  end
end
