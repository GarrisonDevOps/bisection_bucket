# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module YamlProcessor
        module Result
          extend ::Gitlab::Utils::Override

          private

          override :build_attributes
          def build_attributes(name)
            job = jobs.fetch(name.to_sym, {})

            super.deep_merge(
              {
                options: {
                  dast_configuration: job[:dast_configuration],
                  identity: job[:identity],
                  policy: execution_policy_job_options(name)
                }.compact,
                secrets: job[:secrets]
              }.compact
            )
          end

          def execution_policy_job_options(job_name)
            ci_config.pipeline_policy_context&.job_options(ref: ci_config.source_ref_path, job_name: job_name)
          end
        end
      end
    end
  end
end
