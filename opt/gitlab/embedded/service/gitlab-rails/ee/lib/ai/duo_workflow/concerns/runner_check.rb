# frozen_string_literal: true

module Ai
  module DuoWorkflow
    module Concerns
      # Finds a runner that Ci::RegisterJobService would hand a Duo Agent Platform
      # workload to, so a green readiness row means a queued flow is actually picked up.
      # The including class provides `container` and `runner_scope`.
      module RunnerCheck
        include ::Gitlab::Utils::StrongMemoize

        # A container can see far more runners than can ever qualify, so the scan stops
        # after this many tagged candidates instead of loading them all.
        RUNNER_CANDIDATE_LIMIT = 100

        def runner_available?
          usable_runner.present?
        end

        def usable_runner_type
          usable_runner&.runner_type
        end

        private

        def usable_runner
          candidate_runners.find { |runner| usable_runner?(runner) }
        end
        strong_memoize_attr :usable_runner

        # rubocop:disable CodeReuse/ActiveRecord -- Scoping across Ci::Runner and Ci::RunnerManager
        def candidate_runners
          # RunnerValidator reads runner.groups per candidate; preloading avoids an N+1.
          runner_scope
            .active
            .online
            .with_tag(::Ai::DuoWorkflows::Workflow.workload_tag_for(container))
            .preload(:runner_managers, :groups)
            .order(id: :desc)
            .limit(self.class::RUNNER_CANDIDATE_LIMIT)
        end

        # With runner restrictions on, only instance runners and the root group's own
        # runners can pass RunnerValidator, so the project's own and subgroup runners
        # would only fill the candidate window with rejects.
        def project_runner_scope(project)
          return project.all_available_runners unless Feature.enabled?(:duo_runner_restrictions, project)

          ::Ci::Runner.from_union(
            [project.available_shared_runners, project_root_group_runners(project)],
            remove_duplicates: false
          )
        end

        def project_root_group_runners(project)
          return ::Ci::Runner.none unless project.group && project.group_runners_enabled?

          ::Ci::Runner.belonging_to_group(project.root_ancestor.id)
        end

        def usable_runner?(runner)
          return false unless ::Ai::DuoWorkflow::RunnerValidator.new(runner, container).valid?

          runner.runner_managers.any? { |manager| RunnerExecutors.docker_compatible?(manager) }
        end
        # rubocop:enable CodeReuse/ActiveRecord
      end
    end
  end
end
