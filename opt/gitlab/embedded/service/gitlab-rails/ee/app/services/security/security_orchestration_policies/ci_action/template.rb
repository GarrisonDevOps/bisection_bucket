# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    module CiAction
      class Template < Base
        include CiConfigurationMetadata

        SCAN_TEMPLATES = {
          'secret_detection' => 'Jobs/Secret-Detection',
          'container_scanning' => 'Jobs/Container-Scanning',
          'sast' => 'Jobs/SAST',
          'sast_iac' => 'Jobs/SAST-IaC',
          'dependency_scanning' => 'Jobs/Dependency-Scanning'
        }.freeze
        EXCLUDED_VARIABLES = %w[
          API_DISCOVERY_DISABLED
          API_FUZZING_DISABLED
          APISEC_DISABLED
          DAST_BAS_DISABLED
          DAST_API_DISABLED
          COVFUZZ_DISABLED
          CONTAINER_SCANNING_DISABLED
          DAST_DISABLED
          DEPENDENCY_SCANNING_DISABLED
          SAST_DISABLED
          SECRET_DETECTION_DISABLED
        ].freeze
        LATEST_TEMPLATE_TYPE = 'latest'
        DEFAULT_TEMPLATE_TYPE = 'default'
        SCAN_TYPES_WITH_VERSIONED_TEMPLATES = {
          dependency_scanning: %w[v2 default latest]
        }.freeze

        def self.scan_template_path(scan_type, template = DEFAULT_TEMPLATE_TYPE)
          scan_template_ci_path = CiAction::Template::SCAN_TEMPLATES[scan_type]

          return scan_template_ci_path if template == DEFAULT_TEMPLATE_TYPE

          return "#{scan_template_ci_path}.#{LATEST_TEMPLATE_TYPE}" if template == LATEST_TEMPLATE_TYPE

          if SCAN_TYPES_WITH_VERSIONED_TEMPLATES[scan_type.to_sym]&.include?(template)
            return "#{scan_template_ci_path}.#{template}"
          end

          scan_template_ci_path
        end

        def config
          ci_configuration = template_ci_configuration(@action[:scan])

          variables = merge_variables(ci_configuration.delete(:variables), @ci_variables)

          ci_configuration.reject! { |job_name, _| hidden_job?(job_name) }
          ci_configuration.transform_keys! { |job_name| generate_job_name_with_index(job_name) }

          ci_configuration.each_value do |job_configuration|
            apply_variables!(job_configuration, variables)
            apply_tags!(job_configuration, @action[:tags])
            apply_defaults!(job_configuration, @action[:scan_settings])
            remove_extends!(job_configuration)
            remove_rule_to_disable_job!(job_configuration)
            merge_configuration_metadata!(job_configuration, @action[:metadata])
          end

          ci_configuration
        end

        private

        def template_ci_configuration(scan_type)
          @opts[:template_cache].fetch(scan_type, template: scan_template, inputs: @opts[:inputs] || {})
        end

        def scan_template
          @action[:template].presence || DEFAULT_TEMPLATE_TYPE
        end

        def hidden_job?(job_name)
          job_name.start_with?('.')
        end

        def apply_variables!(job_configuration, variables)
          job_configuration[:variables] = merge_variables(job_configuration[:variables], variables)
        end

        def merge_variables(template_variables, variables)
          template_variables.to_h.stringify_keys.deep_merge(variables).compact
        end

        def apply_tags!(job_configuration, tags)
          return if tags.blank?

          job_configuration[:tags] = tags
        end

        def apply_defaults!(job_configuration, scan_settings)
          return unless scan_settings&.fetch(:ignore_default_before_after_script, false)

          job_configuration[:before_script] ||= []
          job_configuration[:after_script] ||= []
        end

        def remove_extends!(job_configuration)
          job_configuration.delete(:extends)
        end

        def remove_rule_to_disable_job!(job_configuration)
          job_configuration[:rules]&.reject! do |rule|
            EXCLUDED_VARIABLES.any? { |variable| rule[:if]&.include?("$#{variable}") }
          end
        end
      end
    end
  end
end
