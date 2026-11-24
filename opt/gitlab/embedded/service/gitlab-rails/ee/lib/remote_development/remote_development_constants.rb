# frozen_string_literal: true

module RemoteDevelopment
  # NOTE: Constants are scoped to the use-case namespace in which they are used in production
  #       code (but they may still be referenced by specs or fixtures or factories).
  #       For example, this RemoteDevelopment::WorkspaceOperations::Create::CreateConstants
  #       file contains constants which are only used by classes within that namespace.
  #
  #       See documentation at ../../README.md#constant-declarations for more information.
  module RemoteDevelopmentConstants
    # Please keep alphabetized
    MAIN_COMPONENT_INDICATOR_ATTRIBUTE = "gl/inject-editor"
    REQUIRED_DEVFILE_SCHEMA_VERSION = "2.2.0"

    # Devfile standard only allows name/id to be of the format /'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'/
    # Hence, we do no need to restrict the prefix `gl_`.
    # However, we do that for the 'variables' in the devfile since they do not have any such restriction
    RESTRICTED_PREFIX = "gl-"
  end
end
