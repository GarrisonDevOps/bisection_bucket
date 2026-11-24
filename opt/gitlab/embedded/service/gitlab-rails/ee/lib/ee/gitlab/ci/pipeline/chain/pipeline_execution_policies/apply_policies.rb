# frozen_string_literal: true

# This step merges jobs from the policy pipelines saved in `pipeline_policy_context` onto the project pipeline.
# If a policy pipeline stage is not used in the project pipeline, all jobs from this stage are silently ignored.
#
# When this step is executed for project pipeline, it is only executed
# if Pipeline Execution Policies configurations were loaded in `PipelineExecutionPolicies::EvaluatePolicies`,
# otherwise it's a no-op.
# When executed for a policy pipeline, we collect `override_project_ci` policy stages to apply them
# in the project pipeline.
#
# The step needs to be executed after `Populate` and `PopulateMetadata` steps to ensure that `pipeline.stages` are set,
# and before `StopDryRun` to ensure that the policy jobs are visible for the users when pipeline creation is simulated.
module EE
  module Gitlab
    module Ci
      module Pipeline
        module Chain
          module PipelineExecutionPolicies
            module ApplyPolicies
              include ::Gitlab::Ci::Pipeline::Chain::Helpers
              include ::Gitlab::Utils::StrongMemoize

              def perform!
                policy_context = command.pipeline_policy_context.pipeline_execution_context

                if policy_context.creating_policy_pipeline?
                  collect_policy_pipeline_stages
                elsif policy_context.has_execution_policy_pipelines?
                  clear_project_pipeline
                  merge_policy_jobs
                  usage_tracking.track_enforcement
                end
              rescue ::Gitlab::Ci::Pipeline::JobsInjector::DuplicateJobNameError => e
                error("Pipeline execution policy error: #{e.message}", failure_reason: :config_error)
              end

              def break?
                pipeline.errors.any?
              end

              private

              def collect_policy_pipeline_stages
                # We save declared policy stages in the pipeline context to use them in the main pipeline
                command.pipeline_policy_context.pipeline_execution_context.collect_declared_stages!(declared_stages)
              rescue ::Gitlab::Ci::Pipeline::PipelineExecutionPolicies::OverrideStagesConflictError => e
                # This error is propagated into `EvaluatePolicies` because it can only happen while building
                # the policy pipeline. `EvaluatePolicies` decorates the error with
                # "Pipeline execution policy error:" prefix.
                error(e.message, failure_reason: :config_error)
              end

              def clear_project_pipeline
                # We remove the project pipeline config if pipeline was forced by a policy (no other config found);
                # pipeline_execution_policy_forced?: It means that it is only
                # the DUMMY job to enforce the pipeline without project CI configuration.
                # It means that we need to ignore the project CI configuration.
                pipeline.stages = [] if pipeline.pipeline_execution_policy_forced?
              end

              def merge_policy_jobs
                applicable_policy_pipelines.each_with_index do |policy, index|
                  # Return `nil` is equivalent to "never" otherwise provide the new name.
                  on_conflict = ->(job_name) { job_name + policy.suffix if policy.suffix_on_conflict? }

                  # Instantiate JobsInjector per policy pipeline to keep conflict-based job renaming isolated
                  job_injector = ::Gitlab::Ci::Pipeline::JobsInjector.new(
                    pipeline: pipeline,
                    declared_stages: declared_stages,
                    on_conflict: on_conflict,
                    job_name_mappings: job_name_mappings_for(index))
                  policy.pipeline.stages.each do |stage|
                    job_injector.inject_jobs(jobs: stage.statuses, stage: stage) do |_job|
                      usage_tracking.track_job_execution
                    end
                  rescue ::Gitlab::Ci::Pipeline::JobsInjector::DuplicateJobNameError
                    command.increment_duplicate_job_name_errors_counter(policy.suffix_strategy)
                    raise
                  end
                end
              end

              def applicable_policy_pipelines
                policy_context = command.pipeline_policy_context.pipeline_execution_context

                # If the pipeline has jobs from project CI config and is not ruled out,
                # all policies apply. Otherwise (empty pipeline), filter
                # policies based on their apply_on_empty_pipeline setting.
                return policy_context.policy_pipelines unless command.pipeline_creation_forced_to_continue

                policy_context.empty_pipeline_applicable_policy_pipelines(pipeline)
              end
              strong_memoize_attr :applicable_policy_pipelines

              def declared_stages
                command.yaml_processor_result.stages
              end

              # `applicable_policy_pipelines` is ordered from the lowest to the highest precedence in the
              # hierarchy (project policies first, top-level group last). A policy's `needs` must not be
              # resolvable to jobs contributed by a policy with lower precedence.
              def job_name_mappings_for(index)
                strong_memoize_with(:job_name_mappings_for, index) do
                  all_mappings = [
                    command.yaml_processor_result.job_name_mappings,
                    *applicable_policy_pipelines.drop(index).map(&:job_name_mappings)
                  ]

                  all_mappings.reduce({}) do |combined, mapping|
                    combined.merge(mapping) { |_key, old_names, new_names| (old_names + new_names).uniq }
                  end
                end
              end

              def usage_tracking
                ::Security::PipelineExecutionPolicy::UsageTracking.new(
                  project: project,
                  policy_pipelines: applicable_policy_pipelines
                )
              end
              strong_memoize_attr :usage_tracking
            end
          end
        end
      end
    end
  end
end
