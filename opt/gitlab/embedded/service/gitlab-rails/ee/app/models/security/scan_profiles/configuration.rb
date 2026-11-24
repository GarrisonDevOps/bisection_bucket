# frozen_string_literal: true

module Security
  module ScanProfiles
    class Configuration < ::SecApplicationRecord
      self.table_name = 'security_scan_profile_configurations'

      DEFAULTS = {
        business_logic: { post_review_threads: false }.freeze,
        dependency_scanning_post_processing: Defaults::DependencyScanningPostProcessing::VALUES,
        triage_and_remediation: Defaults::TriageAndRemediation::STANDARD
      }.freeze

      SCHEMAS = {
        business_logic: 'security_profile_business_logic_configuration',
        dependency_scanning: 'security_profile_dependency_scanning_configuration',
        dependency_scanning_post_processing: 'security_profile_dependency_scanning_post_processing_configuration',
        secret_detection: 'security_profile_secret_detection_configuration',
        triage_and_remediation: {
          sbom_ingested: 'security_profile_dependency_scanning_post_processing_configuration',
          sast_false_positive: 'security_profile_sast_false_positive_configuration',
          sast_vulnerability_resolution: 'security_profile_sast_vulnerability_resolution_configuration',
          secret_detection_false_positive: 'security_profile_secret_detection_false_positive_configuration',
          vulnerability_enrichment: 'security_profile_vulnerability_enrichment_configuration'
        },
        sast: 'security_profile_sast_configuration'
      }.freeze

      EMPTY_CONFIGURATION_SCHEMA = 'security_profile_scan_configuration'

      belongs_to :scan_profile, class_name: 'Security::ScanProfile',
        foreign_key: :security_scan_profile_id, inverse_of: :configurations, optional: false
      belongs_to :namespace, optional: false
      has_many :scan_profile_triggers, class_name: 'Security::ScanProfileTrigger',
        foreign_key: :security_scan_profile_configuration_id, inverse_of: :configuration

      delegate :scan_type, to: :scan_profile, allow_nil: true
      attr_accessor :trigger_type # Not persisted, the trigger owns it. Used only for trigger-scoped scan types.

      validates :trigger_type, presence: true, if: :trigger_scoped?

      SCHEMAS.values.flat_map { |schema| schema.is_a?(Hash) ? schema.values : schema }
        .push(EMPTY_CONFIGURATION_SCHEMA).uniq.each do |filename|
          validates :configuration, json_schema: {
            filename: filename, size_limit: 64.kilobytes, detail_errors: true
          }, if: -> { schema_filename == filename }
        end

      def self.trigger_scoped?(scan_type)
        SCHEMAS[scan_type&.to_sym].is_a?(Hash)
      end

      def self.defaults_for(scan_type, trigger_type = nil)
        defaults = DEFAULTS[scan_type&.to_sym]
        defaults = defaults&.dig(trigger_type&.to_sym) if trigger_scoped?(scan_type)

        defaults || {}
      end

      def self.strip_defaults(values, defaults)
        values.to_h.deep_symbolize_keys.each_with_object({}) do |(key, value), result|
          default = defaults[key]

          if value.is_a?(Hash) && default.is_a?(Hash)
            nested = strip_defaults(value, default)
            result[key] = nested unless nested.empty?
          elsif value != default
            result[key] = value
          end
        end
      end

      def self.effective_for(profile, trigger, project: nil)
        return {} unless profile

        config = defaults_for(profile.scan_type, trigger&.trigger_type)
                   .deep_merge((trigger&.configuration&.configuration || {}).deep_symbolize_keys)

        config = apply_duo_overrides(config, project) if project && trigger&.sbom_ingested?

        config
      end

      def self.apply_duo_overrides(config, project)
        return config unless resolve_dependency_bump_enabled?(project)

        auto_remediation = (config[:auto_remediation] || {}).merge(upgrade_policy: 'major')
        config.merge(auto_remediation: auto_remediation)
      end
      private_class_method :apply_duo_overrides

      def self.resolve_dependency_bump_enabled?(project)
        return false unless project

        project.duo_dependency_bump_breaking_changes_available?
      end
      private_class_method :resolve_dependency_bump_enabled?

      private

      def trigger_scoped?
        self.class.trigger_scoped?(scan_type)
      end

      def schema_filename
        schema = SCHEMAS[scan_type&.to_sym]
        schema = schema[trigger_type&.to_sym] if trigger_scoped?

        schema || EMPTY_CONFIGURATION_SCHEMA
      end
    end
  end
end
