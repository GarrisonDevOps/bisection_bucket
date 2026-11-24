# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    module Probes
      module FoundationalFlows
        class CompatibleRunnerProbe < BaseProbe
          extend ::Gitlab::Utils::Override

          validate :check_compatible_runner_exists

          private

          override :success_message
          def success_message
            _('A compatible runner is available.')
          end

          def check_compatible_runner_exists
            return if compatible_runner_exists?

            errors.add(:base, failure_message)
          end

          def failure_message
            if tagged_runners.none?
              format(
                _("No instance runner with the '%{tag}' tag is registered. " \
                  "Register an active instance runner with this tag and a Docker-compatible executor " \
                  "(such as docker, docker-autoscaler, or kubernetes) to run foundational flows."),
                tag: workload_tag
              )
            elsif tagged_runners.active.none?
              format(
                _("All instance runners with the '%{tag}' tag are paused. " \
                  "Unpause at least one to run foundational flows."),
                tag: workload_tag
              )
            elsif active_tagged_runners_with_manager.none?
              format(
                _("No instance runner with the '%{tag}' tag has connected yet. " \
                  "Start the runner so it registers with GitLab before running foundational flows."),
                tag: workload_tag
              )
            else
              format(
                _("No instance runner with the '%{tag}' tag uses a Docker-compatible executor. " \
                  "Reconfigure the runner to use docker, docker-autoscaler, kubernetes, or another " \
                  "Docker-based executor so it can run foundational flows."),
                tag: workload_tag
              )
            end
          end

          # rubocop:disable CodeReuse/ActiveRecord -- Probe needs to scope across Ci::Runner and Ci::RunnerManager
          def compatible_runner_exists?
            tagged_runners.active.preload(:runner_managers).any? do |runner|
              runner.runner_managers.any? { |manager| ::Ai::DuoWorkflow::RunnerExecutors.docker_compatible?(manager) }
            end
          end

          def active_tagged_runners_with_manager
            tagged_runners.active.joins(:runner_managers)
          end
          # rubocop:enable CodeReuse/ActiveRecord

          def tagged_runners
            ::Ci::Runner.instance_type.with_tag(workload_tag)
          end

          def workload_tag
            ::Ai::DuoWorkflows::Workflow::WORKLOAD_TAG
          end
        end
      end
    end
  end
end
