# frozen_string_literal: true

module Gitlab
  module Ci
    module Pipeline
      module SecurityScanProfiles
        class PipelineContext
          def initialize(project:, ref:, pipeline_source:)
            @eligibility_service = ::Security::ScanProfiles::PipelineEligibilityService.new(
              project: project,
              ref: ref,
              pipeline_source: pipeline_source
            )
            @injected_job_names_metadata_map = {}
          end

          delegate :eligible?, :applicable_profiles_triggers, :merge_train_pipeline?, to: :eligibility_service

          def collect_injected_job_names_with_metadata(template_with_metadata)
            job_name_with_metadata = extract_job_names_and_metadata(template_with_metadata)
            @injected_job_names_metadata_map.merge!(job_name_with_metadata)
          end

          def job_injected?(name)
            @injected_job_names_metadata_map.key?(name.to_sym)
          end

          def injected_jobs?
            @injected_job_names_metadata_map.any?
          end

          def each_injected_job_with_profile_id
            @injected_job_names_metadata_map.each do |job_name, metadata|
              profile_id = metadata&.dig(:profile_id)
              yield job_name.to_s, profile_id if profile_id
            end
          end

          def profile_id_for_job(name)
            @injected_job_names_metadata_map.dig(name.to_sym, :profile_id)
          end

          private

          attr_reader :eligibility_service

          def extract_job_names_and_metadata(template)
            metadata_key = ::Security::SecurityOrchestrationPolicies::CiConfigurationMetadata::METADATA_KEY

            template
              .except(*::Gitlab::Ci::Config::Entry::Root::ALLOWED_KEYS)
              .transform_values { |job_config| job_config.is_a?(Hash) ? job_config[metadata_key] : nil }
          end
        end
      end
    end
  end
end
