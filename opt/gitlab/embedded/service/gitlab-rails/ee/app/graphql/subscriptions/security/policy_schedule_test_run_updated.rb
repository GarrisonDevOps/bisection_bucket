# frozen_string_literal: true

module Subscriptions
  module Security
    class PolicyScheduleTestRunUpdated < ::Subscriptions::BaseSubscription
      include Gitlab::Graphql::Laziness

      payload_type ::Types::Security::PolicyScheduleTestRunType

      argument :test_run_id, ::Types::GlobalIDType[::Security::ScheduledPipelineExecutionPolicyTestRun],
        required: true,
        description: 'Global ID of the policy schedule test run.'

      def authorized?(test_run_id:)
        authorize_object_or_gid!(:read_policy_schedule_test_run, gid: test_run_id)
      end
    end
  end
end
