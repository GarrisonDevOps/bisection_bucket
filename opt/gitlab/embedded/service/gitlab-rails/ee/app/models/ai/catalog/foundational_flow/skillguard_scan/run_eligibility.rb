# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module SkillguardScan
        # Automatic SkillGuard runs need the skillguard_analyzer flag on the top-level group and an
        # attached SkillGuard scan profile with a default_branch_pipeline trigger. Which runs are
        # checked is described on `run_eligibility_resolver` in FoundationalFlow::Attributes.
        module RunEligibility
          TRIGGER_TYPE = :default_branch_pipeline

          module_function

          def call(project:, resource:)
            reason = skip_reason(project, resource)
            return true unless reason

            ::Gitlab::AppJsonLogger.info(
              message: "Skipping SkillGuard scan flow: #{reason}",
              project_id: project.id,
              pipeline_id: resource.try(:id)
            )
            false
          end

          def skip_reason(project, pipeline)
            return 'pipeline not found' unless pipeline.is_a?(::Ci::Pipeline)
            return 'skillguard_analyzer is disabled' unless analyzer_enabled?(project)
            return 'no SkillGuard scan profile attached for default branch pipelines' unless profile_attached?(project)

            # Last, so the other skips do not take the lease.
            'pipeline already scanned' unless first_run_for?(pipeline)
          end

          def analyzer_enabled?(project)
            ::Feature.enabled?(:skillguard_analyzer, project.root_ancestor)
          end

          def profile_attached?(project)
            project.security_scan_profile_for(:skillguard, TRIGGER_TYPE).present?
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
            "skillguard_scan_flow:pipeline:#{pipeline.id}"
          end
        end
      end
    end
  end
end
