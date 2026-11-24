# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Pipeline
        module Chain
          module Command
            extend ::Gitlab::Utils::Override

            attr_accessor :security_policy_protected_branch_bypassed

            override :dry_run?
            def dry_run?
              super || creating_policy_pipeline?
            end

            # Policy pipelines are dry runs, but their jobs are merged into the project pipeline
            # and expand CI_PIPELINE_IID at seed time (for example, in `tags`).
            override :allocate_pipeline_iid?
            def allocate_pipeline_iid?
              super || creating_policy_pipeline?
            end

            override :pipeline_policy_context
            def pipeline_policy_context
              sha_context = ::Gitlab::Ci::Pipeline::ShaContext.new(
                before: before_sha,
                after: after_sha,
                source: source_sha,
                checkout: checkout_sha,
                target: target_sha
              )
              self[:pipeline_policy_context] ||= ::Gitlab::Ci::Pipeline::ExecutionPolicies::PipelineContext.new(
                project: project,
                source: source,
                current_user: current_user,
                ref: ref,
                sha_context: sha_context,
                variables_attributes: variables_attributes,
                scan_execution_policy_context_block: scan_execution_policy_context_block,
                pipeline_execution_policy_context_block: pipeline_execution_policy_context_block,
                chat_data: chat_data,
                merge_request: merge_request,
                schedule: schedule,
                bridge: bridge,
                trigger: trigger
              )
            end

            def scan_profile_context
              @scan_profile_context ||= ::Gitlab::Ci::Pipeline::SecurityScanProfiles::PipelineContext.new(
                project: project,
                ref: ref,
                pipeline_source: source
              )
            end

            def increment_duplicate_job_name_errors_counter(suffix_strategy)
              metrics.duplicate_job_name_errors_counter.increment(suffix_strategy: suffix_strategy)
            end

            private

            def creating_policy_pipeline?
              pipeline_policy_context.pipeline_execution_context.creating_policy_pipeline?
            end
          end
        end
      end
    end
  end
end
