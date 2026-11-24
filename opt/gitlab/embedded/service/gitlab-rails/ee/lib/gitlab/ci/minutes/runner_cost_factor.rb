# frozen_string_literal: true

module Gitlab
  module Ci
    module Minutes
      class RunnerCostFactor
        # Gets the cost factor directly from the runners
        # without discounts quota or runner type checks
        def initialize(runner_matcher, project)
          @runner_matcher = runner_matcher
          @project = project
        end

        # Today these are meant to be set the same. https://gitlab.com/gitlab-org/gitlab/-/issues/337245
        # TODO: remove the dependency on project visibility
        def value
          if @project.public?
            @runner_matcher.public_projects_minutes_cost_factor
          else
            @runner_matcher.private_projects_minutes_cost_factor
          end
        end
      end
    end
  end
end
