# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module BlSecurity
        # Automatic BLSA runs need an attached Business Logic scan profile with a merge_request_pipeline
        # trigger, like Vulnerabilities::AiTriage::Eligibility for triage. Merge train pipelines are
        # skipped because they re-run a merge request that was already scanned. Which runs are checked
        # is described on `run_eligibility_resolver` in FoundationalFlow::Attributes.
        module RunEligibility
          TRIGGER_TYPE = :merge_request_pipeline

          module_function

          def call(project:, resource:)
            reason = skip_reason(project, resource)
            return true unless reason

            ::Gitlab::AppJsonLogger.info(
              message: "Skipping BL security flow: #{reason}",
              project_id: project.id,
              pipeline_id: resource.try(:id)
            )
            false
          end

          def skip_reason(project, pipeline)
            return 'pipeline not found' unless pipeline.is_a?(::Ci::Pipeline)
            return 'no Business Logic scan profile attached for merge requests' unless profile_attached?(project)
            return 'Security Review Flow runs instead' if security_review_replaces_scan?(project)
            return 'merge train pipeline' if pipeline.merge_train_pipeline?
            return 'merge request pipeline is stale' if stale?(pipeline)

            # Last, so the other skips do not take the lease.
            'pipeline already scanned' unless first_run_for?(pipeline)
          end

          def security_review_replaces_scan?(project)
            ::Gitlab::Duo::SecurityReview::Automatic.replaces_business_logic_scan?(project)
          end

          def profile_attached?(project)
            project.security_scan_profile_for(:business_logic, TRIGGER_TYPE).present?
          end

          # Pipeline hooks can report success more than once for a pipeline: late hook workers
          # read the current status, and a retried job takes the pipeline back through running.
          def first_run_for?(pipeline)
            ::Gitlab::ExclusiveLease.new(lease_key(pipeline), timeout: 1.day.to_i).try_obtain
          end

          # Called when the run was refused after the lease was taken, so a retried job can scan the pipeline.
          def release(pipeline)
            key = lease_key(pipeline)
            ::Gitlab::ExclusiveLease.cancel(key, ::Gitlab::ExclusiveLease.get_uuid(key))
          end

          def lease_key(pipeline)
            "bl_security_flow:pipeline:#{pipeline.id}"
          end

          # Same check fix_pipeline/v1 applies in Ai::FlowTriggers::EventTriggerService.
          def stale?(pipeline)
            pipeline.merge_request? && !pipeline.merge_request.diff_head_pipeline?(pipeline)
          end
        end
      end
    end
  end
end
