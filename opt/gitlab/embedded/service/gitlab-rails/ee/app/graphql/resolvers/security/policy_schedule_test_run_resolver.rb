# frozen_string_literal: true

module Resolvers
  module Security
    class PolicyScheduleTestRunResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type Types::Security::PolicyScheduleTestRunType, null: true

      authorize :read_policy_schedule_test_run

      description 'Find a policy schedule test run by ID.'

      argument :id, ::Types::GlobalIDType[::Security::ScheduledPipelineExecutionPolicyTestRun],
        required: true,
        description: 'Global ID of the policy schedule test run.'

      def resolve(id:)
        test_run = ::Gitlab::Graphql::Lazy.force(GitlabSchema.find_by_gid(id))

        raise_resource_not_available_error! unless test_run

        authorize!(test_run)

        test_run
      end
    end
  end
end
