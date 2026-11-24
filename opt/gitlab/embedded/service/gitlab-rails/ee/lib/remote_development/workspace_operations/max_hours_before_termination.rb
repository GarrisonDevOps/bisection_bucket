# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    class MaxHoursBeforeTermination
      # NOTE: see the following issue for the reasoning behind this value being the hard maximum termination limit:
      #      https://gitlab.com/gitlab-org/gitlab/-/issues/471994
      # This may be configurable again in the future if we move away from Personal Access Tokens, but for now
      # it's a hardcoded constant.
      MAX_HOURS_BEFORE_TERMINATION = 8760
    end
  end
end
