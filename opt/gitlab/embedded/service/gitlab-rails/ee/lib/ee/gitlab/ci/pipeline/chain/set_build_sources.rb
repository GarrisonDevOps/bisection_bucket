# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Pipeline
        module Chain
          module SetBuildSources
            extend ::Gitlab::Utils::Override

            override :pipeline_execution_policy_build?
            def pipeline_execution_policy_build?
              command.pipeline_policy_context.pipeline_execution_context.creating_policy_pipeline?
            end

            override :scan_execution_policy_build?
            def scan_execution_policy_build?(build)
              command.pipeline_policy_context.scan_execution_context(pipeline.source_ref_path)
                .job_injected?(build.name)
            end

            override :security_scan_profile_build?
            def security_scan_profile_build?(build)
              return true if pipeline.config_source.to_s == 'security_scan_profiles_source'

              command.scan_profile_context.job_injected?(build.name)
            end
          end
        end
      end
    end
  end
end
