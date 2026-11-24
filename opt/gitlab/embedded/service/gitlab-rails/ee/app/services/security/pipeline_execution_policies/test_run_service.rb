# frozen_string_literal: true

module Security
  module PipelineExecutionPolicies
    class TestRunService
      include Gitlab::Utils::StrongMemoize

      def initialize(policy:, project:, user:)
        @policy = policy
        @project = project
        @user = user
      end

      def execute
        return error('Policy must be a pipeline_execution_schedule_policy') unless valid_policy_type?
        return error('User is not allowed to trigger test runs for this policy') unless authorized_user?
        return error('Project is not in policy scope') unless project_in_scope?

        test_run = create_test_run
        return error(test_run.errors.full_messages.join(', ')) unless test_run.persisted?

        enqueue_pipeline_creation(test_run)
      end

      private

      attr_reader :policy, :project, :user

      def valid_policy_type?
        policy.type_pipeline_execution_schedule_policy?
      end

      def project_in_scope?
        policy_configuration_applies_to_project? && policy.scope_applicable?(project)
      end

      # scope_applicable? treats an empty scope as "applies to everything", which is only
      # safe when candidates are pre-restricted to the configuration's namespace. The
      # project here is user-selected, so verify namespace reachability first.
      def policy_configuration_applies_to_project?
        project
          .all_security_orchestration_policy_configurations(include_invalid: true)
          .any? { |configuration| configuration.id == policy.security_orchestration_policy_configuration_id }
      end

      def authorized_user?
        Ability.allowed?(user, :push_code, policy.security_policy_management_project)
      end

      def create_test_run
        Security::ScheduledPipelineExecutionPolicyTestRun.create(
          security_policy: policy,
          project: project,
          state: :pending
        )
      end

      def enqueue_pipeline_creation(test_run)
        ::Security::PipelineExecutionSchedulePolicies::CreateTestRunPipelineWorker.perform_async(test_run.id)

        success(test_run: test_run)
      end

      def success(payload = {})
        ServiceResponse.success(payload: payload)
      end

      def error(message, payload = {})
        ServiceResponse.error(message: message, payload: payload)
      end
    end
  end
end
