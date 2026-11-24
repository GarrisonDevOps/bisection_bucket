# frozen_string_literal: true

module Mutations
  module Security
    module PipelineExecutionSchedulePolicy
      class TestRun < BaseMutation
        graphql_name 'PipelineExecutionSchedulePolicyTestRun'
        description 'Triggers a test-run for a Scheduled Pipeline Execution Policy on a specific project.'

        include FindsProject

        authorize :create_policy_schedule_test_run

        authorize_granular_token permissions: :create_policy_schedule_test_run,
          boundary_argument: :project_path, boundary_type: :project

        argument :policy_id, ::Types::GlobalIDType[::Security::Policy],
          required: true,
          description: 'Global ID of the pipeline execution schedule policy to test.'

        argument :project_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the project to run the test on.'

        field :test_run, ::Types::Security::PolicyScheduleTestRunType,
          null: true,
          description: 'Test-run record created.'

        def resolve(policy_id:, project_path:)
          project = authorized_find!(project_path)

          policy = find_policy(policy_id)
          return { test_run: nil, errors: ['Policy not found'] } unless policy

          result = ::Security::PipelineExecutionPolicies::TestRunService
            .new(policy: policy, project: project, user: current_user)
            .execute

          if result.success?
            { test_run: result.payload[:test_run], errors: [] }
          else
            { test_run: result.payload[:test_run], errors: [result.message] }
          end
        end

        private

        def find_policy(policy_id)
          ::Gitlab::Graphql::Lazy.force(GitlabSchema.find_by_gid(policy_id))
        end
      end
    end
  end
end
