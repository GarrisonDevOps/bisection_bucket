# frozen_string_literal: true

module Gitlab
  module Ci
    class Config
      module SecurityScanProfiles
        class Processor
          DEFAULT_APPLICATION_SECURITY_STAGE = 'application-security-testing'
          DEFAULT_BUILD_STAGE = 'build'
          DEFAULT_STAGES = Gitlab::Ci::Config::Entry::Stages.default
          # Keeps profile job names unique to avoid in-pipeline collision with policy jobs
          JOB_NAME_SUFFIX = 'profile'

          def initialize(config, context, ref, source)
            @config = config.deep_dup
            @context = context
            @project = context.project
            @ref = ref
            @source = source
          end

          def perform
            return config unless process_scan_profiles?
            return config unless valid_stages_config?

            ensure_workflow_exists
            apply_scan_profiles

            config
          end

          private

          attr_reader :project, :context, :ref, :source, :config

          def process_scan_profiles?
            return false unless scan_profile_context&.eligible?

            # Profile jobs are the whole train pipeline when the project has no CI config of its own.
            # Skipping them would leave the pipeline empty and drop the MR from the train.
            !scan_profile_context.merge_train_pipeline? || config.empty?
          end

          def valid_stages_config?
            config[:stages].blank? || Entry::Stages.new(config[:stages]).valid?
          end

          def ensure_workflow_exists
            config[:workflow] = { rules: [{ when: 'always' }] } if config.empty?
          end

          def apply_scan_profiles
            defined_stages = config[:stages].presence || DEFAULT_STAGES.clone
            merge_scans_from_profiles(config, defined_stages)
            finalize_stages(defined_stages)
          end

          def finalize_stages(defined_stages)
            config[:stages] = cleanup_stages(defined_stages + Array.wrap(config[:stages]))
            config.delete(:stages) if config[:stages].blank?
          end

          def cleanup_stages(stages)
            stages.uniq!
            return if stages == DEFAULT_STAGES

            stages
          end

          def merge_scans_from_profiles(merged_config, defined_stages)
            return if profile_templates[:pipeline_scan].blank?

            unless defined_stages.include?(DEFAULT_APPLICATION_SECURITY_STAGE)
              insert_stage_after_or_prepend(defined_stages, DEFAULT_APPLICATION_SECURITY_STAGE,
                ['.pre', DEFAULT_BUILD_STAGE])
            end

            pipeline_scans = profile_templates[:pipeline_scan]
            pipeline_scans.each_value do |value|
              next if value.frozen?
              next if value[:stage].in?(::Gitlab::Ci::Config::Stages::EDGES)

              value[:stage] = DEFAULT_APPLICATION_SECURITY_STAGE
            end

            collect_injected_job_names(pipeline_scans)
            jobs_without_metadata = strip_metadata_from_jobs(pipeline_scans)
            merged_config.deep_merge!(jobs_without_metadata)
            prioritize_glas!(merged_config)
          end

          def collect_injected_job_names(pipeline_scans)
            scan_profile_context.collect_injected_job_names_with_metadata(pipeline_scans)
          end

          def strip_metadata_from_jobs(pipeline_scans)
            metadata_key = ::Security::SecurityOrchestrationPolicies::CiConfigurationMetadata::METADATA_KEY

            pipeline_scans.transform_values do |job_config|
              next job_config unless job_config.is_a?(Hash)

              job_config.except(metadata_key)
            end
          end

          def scan_profile_context
            @scan_profile_context ||= context.scan_profile_context
          end

          def profile_templates
            @profile_templates ||= begin
              ::Security::SecurityOrchestrationPolicies::ScanPipelineService
               .new(context, job_name_suffix: JOB_NAME_SUFFIX)
               .execute(all_profiles)
            rescue ::Gitlab::Ci::Config::TimeoutError
              raise
            rescue ::Gitlab::Ci::Config::ConfigError => e
              triggers = scan_profile_context.applicable_profiles_triggers
              ::Gitlab::ErrorTracking.track_exception(
                e,
                {
                  project_id: project.id,
                  ref: ref,
                  pipeline_source: source,
                  profile_ids: triggers.map { |trigger| trigger.scan_profile.id }.uniq,
                  trigger_count: triggers.size
                },
                { error_type: 'security_scan_profile_config_error' }
              )

              raise ::Gitlab::Ci::Config::ConfigError,
                'Security scan profile configuration is invalid and the pipeline cannot run.'
            end
          end

          def all_profiles
            scan_profile_context.applicable_profiles_triggers.map do |trigger|
              {
                scan: trigger.scan_profile.scan_type,
                template: trigger.scan_profile.ci_template_name,
                variables: trigger.ci_variables,
                inputs: trigger.ci_inputs,
                metadata: { profile_id: trigger.scan_profile.id }
              }
            end
          end

          def insert_stage_after_or_prepend(stages, insert_stage_name, after_stages)
            stage_index = after_stages.filter_map { |stage| stages.index(stage) }.max

            if stage_index.nil?
              stages.unshift(insert_stage_name)
            else
              stages.insert(stage_index + 1, insert_stage_name)
            end
          end

          def prioritize_glas!(config)
            config[:variables] = (config[:variables] || {}).merge(
              { 'GITLAB_ADVANCED_SAST_ENABLED' => 'true' },
              # to allow MR pipelines to run GLAS. For additional details see:
              # https://docs.gitlab.com/user/application_security/detect/security_configuration/#use-security-scanning-tools-with-merge-request-pipelines
              { 'AST_ENABLE_MR_PIPELINES' => 'true' }
            )
            config
          end
        end
      end
    end
  end
end
