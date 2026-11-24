# frozen_string_literal: true

module Ai
  module DuoWorkflow
    # Which runner executors can host a Duo Agent Platform workload.
    module RunnerExecutors
      # Explicit list: docker_windows and docker_ssh* carry the docker prefix but
      # cannot run the Linux-only workload image.
      DOCKER_COMPATIBLE_TYPES = %w[docker docker_autoscaler docker_machine kubernetes].freeze

      class << self
        def docker_compatible?(runner_manager)
          DOCKER_COMPATIBLE_TYPES.include?(runner_manager.executor_type.to_s)
        end
      end
    end
  end
end
