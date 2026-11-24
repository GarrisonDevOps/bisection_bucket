# frozen_string_literal: true

module EE
  module Types
    module SubscriptionType
      extend ActiveSupport::Concern

      prepended do
        def self.authorization_scopes
          [:api, :read_api, :ai_features]
        end

        field :ai_completion_response,
          subscription: ::Subscriptions::AiCompletionResponse, null: true,
          scopes: [:api, :read_api, :ai_features],
          description: 'Triggered when a response from AI integration is received.',
          experiment: { milestone: '15.11' }

        field :issuable_weight_updated,
          subscription: Subscriptions::IssuableUpdated, null: true,
          description: 'Triggered when the weight of an issuable is updated.'

        field :issuable_iteration_updated,
          subscription: Subscriptions::IssuableUpdated, null: true,
          description: 'Triggered when the iteration of an issuable is updated.'

        field :issuable_health_status_updated,
          subscription: Subscriptions::IssuableUpdated, null: true,
          description: 'Triggered when the health status of an issuable is updated.'

        field :issuable_epic_updated,
          subscription: Subscriptions::IssuableUpdated, null: true,
          description: 'Triggered when the epic of an issuable is updated.'

        field :merge_request_ai_suggested_reviewers_updated,
          subscription: Subscriptions::IssuableUpdated, null: true,
          experiment: { milestone: '19.5' },
          description: 'Triggered when the AI-recommended reviewers of a merge request are updated.'

        field :workflow_events_updated,
          subscription: ::Subscriptions::Ai::DuoWorkflows::WorkflowEventsUpdated, null: true,
          description: 'Triggered when the checkpoints/events of a workflow is updated.'

        field :security_policy_project_created,
          subscription: Subscriptions::Security::PolicyProjectCreated, null: true,
          description: 'Triggered when the security policy project is created for a specific group or project.',
          experiment: { milestone: '17.3' },
          directives: granular_scope_directive(
            permissions: :read_security_policy,
            boundaries: [
              { boundary_argument: :full_path, boundary_type: :project },
              { boundary_argument: :full_path, boundary_type: :group }
            ]
          )

        field :security_policy_schedule_test_run_updated,
          subscription: Subscriptions::Security::PolicyScheduleTestRunUpdated, null: true,
          description: 'Triggered when a policy schedule test run state is updated.',
          experiment: { milestone: '19.0' }

        field :cd_rollout_updated,
          subscription: ::Subscriptions::Cd::RolloutUpdated, null: true,
          scopes: [:api, :read_api, :ai_features],
          description: 'Triggered when a rollout status changes in an application, ' \
            'carrying the new deployment status and, when one applies, a Duo session to open.',
          experiment: { milestone: '19.3' }

        field :cd_application_health_updated,
          subscription: ::Subscriptions::Cd::ApplicationHealthUpdated, null: true,
          # Deliberately narrower than cd_rollout_updated: this payload carries no AI/Duo data,
          # so :ai_features-scoped tokens are not granted access (matches the BaseField default,
          # made explicit here to document the choice).
          scopes: [:api, :read_api],
          description: 'Triggered when the health of an application in an organization changes.',
          experiment: { milestone: '19.3' }

        field :cd_service_updated,
          subscription: ::Subscriptions::Cd::ServiceUpdated, null: true,
          # Deliberately narrower than cd_rollout_updated: this payload carries no AI/Duo data,
          # so :ai_features-scoped tokens are not granted access (matches the BaseField default,
          # made explicit here to document the choice).
          scopes: [:api, :read_api],
          description: 'Triggered when the state of a service in an application changes.',
          experiment: { milestone: '19.3' }

        field :cd_environment_service_updated,
          subscription: ::Subscriptions::Cd::EnvironmentServiceUpdated, null: true,
          scopes: [:api, :read_api],
          description: 'Triggered when a service finishes deploying to an environment.',
          experiment: { milestone: '19.4' }

        field :cd_deployment_updated,
          subscription: ::Subscriptions::Cd::DeploymentUpdated, null: true,
          # Deliberately narrower than cd_rollout_updated: this payload carries no AI/Duo data,
          # so :ai_features-scoped tokens are not granted access (matches the BaseField default,
          # made explicit here to document the choice).
          scopes: [:api, :read_api],
          description: 'Triggered when the state of a deployment in an application changes.',
          experiment: { milestone: '19.3' }

        field :cd_rollout_step_updated,
          subscription: ::Subscriptions::Cd::RolloutStepUpdated, null: true,
          scopes: [:api, :read_api],
          description: 'Triggered when the state or error of a rollout step changes.',
          experiment: { milestone: '19.3' }

        field :cd_rollout_gate_updated,
          subscription: ::Subscriptions::Cd::RolloutGateUpdated, null: true,
          scopes: [:api, :read_api],
          description: 'Triggered when a rollout approval gate opens or is resolved.',
          experiment: { milestone: '19.4' }

        field :cd_version_set_updated,
          subscription: ::Subscriptions::Cd::VersionSetUpdated, null: true,
          scopes: [:api, :read_api],
          description: 'Triggered when the derived status of a release (version set) in an application changes.',
          experiment: { milestone: '19.4' }
      end
    end
  end
end
