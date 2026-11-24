# frozen_string_literal: true

module EE
  module GraphqlTriggers
    extend ActiveSupport::Concern

    prepended do
      def self.ai_completion_response(message)
        subscription_arguments = {
          user_id: message.user.to_gid,
          ai_action: message.ai_action.to_s
        }

        if message.client_subscription_id && !message.user?
          subscription_arguments[:client_subscription_id] = message.client_subscription_id
        end

        ::GitlabSchema.subscriptions.trigger(:ai_completion_response, subscription_arguments, message.to_h)

        # Once all clients `ai_action` we can remove this trigger duplicate .
        # Clients that use the `ai_action` parameter to subscribe on, no longer need to subscribe on the
        # `resource_id`. This enables us to broadcast chat messages to clients, regardless of their `resource_id`.
        # https://gitlab.com/gitlab-org/gitlab/-/issues/423080
        ::GitlabSchema.subscriptions.trigger(
          :ai_completion_response,
          subscription_arguments.except(:ai_action).merge(resource_id: message.resource&.to_global_id),
          message.to_h)
      end

      def self.issuable_weight_updated(issuable)
        ::GitlabSchema.subscriptions.trigger(:issuable_weight_updated, { issuable_id: issuable.to_gid }, issuable)
      end

      def self.issuable_iteration_updated(issuable)
        ::GitlabSchema.subscriptions.trigger(:issuable_iteration_updated, { issuable_id: issuable.to_gid }, issuable)
      end

      def self.issuable_health_status_updated(issuable)
        ::GitlabSchema.subscriptions.trigger(
          :issuable_health_status_updated, { issuable_id: issuable.to_gid }, issuable
        )
      end

      def self.issuable_epic_updated(issuable)
        ::GitlabSchema.subscriptions.trigger(:issuable_epic_updated, { issuable_id: issuable.to_gid }, issuable)
      end

      def self.merge_request_ai_suggested_reviewers_updated(merge_request)
        ::GitlabSchema.subscriptions.trigger(
          :merge_request_ai_suggested_reviewers_updated, { issuable_id: merge_request.to_gid }, merge_request
        )
      end

      # Takes a checkpoint, or the workflow itself when it has no checkpoint to publish yet.
      def self.workflow_events_updated(event)
        workflow = event.is_a?(::Ai::DuoWorkflows::Workflow) ? event : event.workflow

        ::GitlabSchema.subscriptions.trigger(:workflow_events_updated, { workflow_id: workflow.to_gid }, event)
      end

      def self.security_policy_project_created(container, status, security_policy_project, errors)
        error_message = errors.any? ? errors.join(' ') : nil

        ::GitlabSchema.subscriptions.trigger(
          :security_policy_project_created,
          { full_path: container.full_path },
          { status: status, errors: errors, error_message: error_message, project: security_policy_project }
        )
      end

      def self.security_policy_schedule_test_run_updated(test_run)
        ::GitlabSchema.subscriptions.trigger(
          :security_policy_schedule_test_run_updated,
          { test_run_id: test_run.to_global_id },
          test_run
        )
      end

      # One push carrying both the new deployment status (for the stage dot) and,
      # when one applies, the Duo session to open in the sidebar.
      #
      # reason:              one of Cd::RolloutUpdateReasonEnum's underlying values
      #                      (:deployment_failed, :deployment_created)
      # rollout_environment: the environment whose state changed (drives the dot); optional
      # thread:              the Duo session to open; optional (omitted e.g. on plain success)
      def self.cd_rollout_updated(rollout, reason, rollout_environment: nil, thread: nil)
        ::GitlabSchema.subscriptions.trigger(
          :cd_rollout_updated,
          { application_id: rollout.application.to_gid },
          {
            rollout: rollout,
            rollout_environment: rollout_environment,
            thread: thread,
            reason: reason
          }
        )
      end

      # Pushes an application whose health label changed, keyed by organization so the
      # applications list (organization.cdApplications) updates the badge live.
      def self.cd_application_health_updated(application)
        ::GitlabSchema.subscriptions.trigger(
          :cd_application_health_updated,
          { organization_id: application.organization.to_gid },
          application
        )
      end

      # Pushes a service whose state changed, keyed by application so the
      # services list (application.services) updates live.
      def self.cd_service_updated(service)
        ::GitlabSchema.subscriptions.trigger(
          :cd_service_updated,
          { application_id: service.application.to_gid },
          service
        )
      end

      # Pushes the service of a finished deployment, keyed by environment so the
      # deployed applications table on the environment page updates live.
      def self.cd_environment_service_updated(deployment)
        ::GitlabSchema.subscriptions.trigger(
          :cd_environment_service_updated,
          { environment_id: deployment.rollout_environment.environment.to_gid },
          deployment.service
        )
      end

      # Pushes a deployment whose state changed, keyed by application so the
      # deployment status (for example, the rollout environment's stage dot) updates live.
      def self.cd_deployment_updated(deployment)
        ::GitlabSchema.subscriptions.trigger(
          :cd_deployment_updated,
          { application_id: deployment.service.application.to_gid },
          deployment
        )
      end

      def self.cd_rollout_step_updated(step)
        ::GitlabSchema.subscriptions.trigger(
          :cd_rollout_step_updated,
          { rollout_id: step.rollout.to_gid },
          step
        )
      end

      def self.cd_rollout_gate_updated(rollout)
        ::GitlabSchema.subscriptions.trigger(
          :cd_rollout_gate_updated,
          { rollout_id: rollout.to_gid },
          rollout
        )
      end

      # Pushes a version set (release) whose derived status changed, keyed by
      # application so the releases list (application.versionSets) updates live.
      def self.cd_version_set_updated(version_set)
        ::GitlabSchema.subscriptions.trigger(
          :cd_version_set_updated,
          { application_id: version_set.application.to_gid },
          version_set
        )
      end
    end
  end
end
