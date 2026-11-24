# frozen_string_literal: true

module Resolvers
  module Security
    class PolicyTestRunsResolver < BaseResolver
      type Types::Security::PolicyScheduleTestRunType.connection_type, null: true
      description 'Find test runs for a security policy.'

      def resolve
        policy_index = object[:policy_index]
        policy_type = object[:type]
        return [] if policy_index.nil? || policy_type != ::Security::Policy::PIPELINE_EXECUTION_SCHEDULE_POLICY_TYPE

        policy_configuration = object[:config]
        return [] unless policy_configuration

        security_policy = find_security_policy(policy_configuration, policy_index)
        return [] unless security_policy

        find_test_runs(security_policy)
      end

      private

      def find_security_policy(policy_configuration, policy_index)
        ::Security::Policy
          .for_policy_configuration(policy_configuration)
          .type_pipeline_execution_schedule_policy
          .for_policy_index(policy_index)
          .first
      end

      def find_test_runs(security_policy)
        ::Security::ScheduledPipelineExecutionPolicyTestRun
          .for_policy(security_policy)
          .with_associations
      end
    end
  end
end
