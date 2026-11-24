# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceStateHelpers
    include WorkspaceOperations::States

    # @return [Boolean]
    def actual_state_terminated?
      actual_state == TERMINATED
    end

    # @return [Boolean]
    def desired_state_running?
      desired_state == RUNNING
    end

    # @return [Boolean]
    def desired_state_restart_requested?
      desired_state == RESTART_REQUESTED
    end

    # @return [Boolean]
    def desired_state_stopped?
      desired_state == STOPPED
    end

    # @return [Boolean]
    def desired_state_terminated?
      desired_state == TERMINATED
    end
  end
end
