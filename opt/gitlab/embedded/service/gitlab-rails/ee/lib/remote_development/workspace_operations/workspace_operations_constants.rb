# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    # NOTE: Constants are scoped to the namespace in which they are used in production
    #       code (but they may still be referenced by specs or fixtures or factories).
    #       For example, this RemoteDevelopment::WorkspaceOperations::WorkspaceOperationsConstants
    #       file only contains constants which are used by multiple sub-namespaces
    #       of WorkspaceOperations, such as Create and Reconcile.
    #       Constants which are only used by a specific use-case sub-namespace
    #       like Create or Reconcile should be contained in the corresponding
    #       constants class such as CreateConstants or ReconcileConstants.
    #
    #       Multiple related constants may be declared in their own dedicated
    #       namespace, such as RemoteDevelopment::WorkspaceOperations::States.
    #
    #       See documentation at ../README.md#constant-declarations for more information.
    module WorkspaceOperationsConstants
      # Please keep alphabetized
      ANNOTATION_KEY_INCLUDE_IN_PARTIAL_RECONCILIATION = :"workspaces.gitlab.com/include-in-partial-reconciliation"
      ENV_VAR_SECRET_SUFFIX = "-env-var"
      FILE_SECRET_SUFFIX = "-file"
      INTERNAL_COMMAND_LABEL = "gl-internal"
      INTERNAL_BLOCKING_COMMAND_LABEL = "#{INTERNAL_COMMAND_LABEL}-blocking".freeze
      SECRETS_INVENTORY = "-secrets-inventory"
      VARIABLES_VOLUME_DEFAULT_MODE = 0o774
      VARIABLES_VOLUME_NAME = "gl-workspace-variables"
      VARIABLES_VOLUME_PATH = "/.workspace-data/variables/file"
      WORKSPACE_DATA_VOLUME_PATH = "/projects"
      WORKSPACE_INVENTORY = "-workspace-inventory"
      WORKSPACE_LOGS_DIR = "#{WORKSPACE_DATA_VOLUME_PATH}/workspace-logs".freeze
      WORKSPACE_RECONCILED_ACTUAL_STATE_FILE_NAME = "gl_workspace_reconciled_actual_state.txt"
      WORKSPACE_RECONCILED_ACTUAL_STATE_FILE_PATH =
        "#{VARIABLES_VOLUME_PATH}/#{WORKSPACE_RECONCILED_ACTUAL_STATE_FILE_NAME}".freeze
      # Pinned by the digest of the multi-platform image index (linux/amd64 and linux/arm64), so the container
      # runtime pulls the variant matching the node. The tools run inside the workspace's main container, so the
      # default devfile image (settings/default_devfile.yaml) must be built for the same platforms.
      WORKSPACE_TOOLS_IMAGE = "registry.gitlab.com/gitlab-org/gitlab-build-images:20261013232549-workspaces-tools@sha256:ec12f2a705dac25bc0aa6dcf80b01a5de35ece297a258e5677dc023c82ee7ef6" # rubocop:disable Layout/LineLength, Lint/RedundantCopDisableDirective -- Docker image should not be in multi-lines
    end
  end
end
