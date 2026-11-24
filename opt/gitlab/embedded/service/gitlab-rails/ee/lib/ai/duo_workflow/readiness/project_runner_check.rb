# frozen_string_literal: true

module Ai
  module DuoWorkflow
    module Readiness
      # Runner readiness for a project without a user, for callers such as compliance controls.
      class ProjectRunnerCheck
        include Concerns::RunnerCheck

        def initialize(project)
          @project = project
        end

        private

        attr_reader :project

        alias_method :container, :project

        def runner_scope
          project_runner_scope(project)
        end
      end
    end
  end
end
