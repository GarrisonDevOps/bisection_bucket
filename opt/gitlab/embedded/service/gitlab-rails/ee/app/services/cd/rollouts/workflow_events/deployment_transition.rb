# frozen_string_literal: true

module Cd
  module Rollouts
    module WorkflowEvents
      class DeploymentTransition
        def initialize(rollout, event)
          @rollout = rollout
          @event = event
        end

        def execute
          case event.type
          when WorkflowEventTypes::SERVICE_STARTED
            transition(:start_deploying)
          when WorkflowEventTypes::SERVICE_SUCCEEDED
            transition(:mark_healthy)
          when WorkflowEventTypes::SERVICE_FAILED
            transition(:fail_deployment)
          end
        end

        private

        attr_reader :rollout, :event

        def transition(deployment_event)
          return unless event.environment_name && event.service_name

          deployment = find_deployment
          return log_unmatched_deployment unless deployment

          from_state = deployment.state

          ::Cd::Deployment.transaction do
            # rubocop:disable GitlabSecurity/PublicSend -- deployment_event is one of the three symbols passed above, never request data
            next unless deployment.public_send(deployment_event)

            # rubocop:enable GitlabSecurity/PublicSend

            deployment.deployment_transitions.create!(
              event: deployment_event.to_s,
              from_state: from_state,
              to_state: deployment.state,
              principal: 'system:autoflow',
              reason: event.error
            )
          end
        end

        def find_deployment
          rollout_environment = rollout.rollout_environments.with_environment_name(event.environment_name).first
          return unless rollout_environment

          service = rollout.application.services.with_name(event.service_name).first
          return unless service

          rollout_environment.deployments.for_service(service).first
        end

        def log_unmatched_deployment
          Cd::Logger.info(
            message: 'Unmatched CD rollout workflow event deployment',
            rollout_id: rollout.id,
            rollout_environment_name: event.environment_name,
            cd_service_name: event.service_name
          )
        end
      end
    end
  end
end
