# frozen_string_literal: true

# This step collects configurations for Pipeline Execution Policies and builds isolated pipelines for each policy.
# The resulting pipeline objects are saved on the `command`.
# The jobs of the policy pipelines are merged onto the project pipeline later in the chain,
# in the `PipelineExecutionPolicies::ApplyPolicies` step.
#
# The step needs to be executed:
# - After `AssignPartition` to ensure that all policy pipelines are built using the same `partition_id`.
# - Before `Skip` step to enforce pipeline with policies regardless of `ci.skip` options.
# - Before `Config::Content` step to be able to force the pipeline creation
#   with Pipeline Execution Policies if there is no `.gitlab-ci.yml` in the project.
#
# If there are applicable policies and they return an error, the pipeline creation will be aborted.
# If the policy pipelines are filtered out by rules, they are ignored and the pipeline creation continues as usual.
module EE
  module Gitlab
    module Ci
      module Pipeline
        module Chain
          module PipelineExecutionPolicies
            module EvaluatePolicies
              include ::Gitlab::Ci::Pipeline::Chain::Helpers
              extend ::Gitlab::Utils::Override

              override :perform!
              def perform!
                command
                  .pipeline_policy_context
                  .pipeline_execution_context
                  .build_policy_pipelines!(pipeline.partition_id) do |error_message|
                  break error("Pipeline execution policy error: #{error_message}", failure_reason: :config_error)
                end
              end

              override :break?
              def break?
                pipeline.errors.any?
              end
            end
          end
        end
      end
    end
  end
end
