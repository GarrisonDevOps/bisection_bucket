# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module YamlProcessor
        extend ::Gitlab::Utils::Override
        include ::Gitlab::Utils::StrongMemoize

        private

        override :ci_config_opts
        def ci_config_opts
          super.merge(pipeline_policy_context: pipeline_policy_context)
        end

        override :validate_job!
        def validate_job!(name, job)
          super

          validate_job_identity!(name, job)
        end

        def validate_job_stage!(name, job)
          super
          return if pipeline_policy_context.pipeline_execution_context.valid_stage?(job[:stage])

          error!("#{name} job: chosen stage `#{job[:stage]}` is reserved for Pipeline Execution Policies")
        end

        def pipeline_policy_context
          # We instantiate default PipelineContext as fallback to validate reserved stages
          # in case `pipeline_policy_context` is not defined
          opts[:pipeline_policy_context] ||
            ::Gitlab::Ci::Pipeline::ExecutionPolicies::PipelineContext.new(project: project)
        end

        def validate_job_identity!(name, job)
          return if job[:identity].blank?

          unless google_cloud_support_saas_feature?
            error!("#{name} job: #{s_('GoogleCloud|The google_cloud_support feature is not available')}")
          end

          integration = project.google_cloud_platform_workload_identity_federation_integration
          if integration.nil?
            error!("#{name} job: #{s_('GoogleCloud|The Google Cloud Identity and Access Management ' \
                                      'integration is not configured for this project')}")
          end

          return if integration.active?

          error!("#{name} job: #{s_('GoogleCloud|The Google Cloud Identity and Access Management ' \
                                    'integration is not enabled for this project')}")
        end

        def google_cloud_support_saas_feature?
          ::Gitlab::Saas.feature_available?(:google_cloud_support)
        end
        strong_memoize_attr :google_cloud_support_saas_feature?
      end
    end
  end
end
