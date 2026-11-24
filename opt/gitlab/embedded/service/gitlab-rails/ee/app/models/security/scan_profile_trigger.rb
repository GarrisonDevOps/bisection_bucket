# frozen_string_literal: true

module Security
  class ScanProfileTrigger < ::SecApplicationRecord
    self.table_name = 'security_scan_profile_triggers'

    PIPELINE_RELATED_TRIGGER_TYPE = %w[
      default_branch_pipeline
      merge_request_pipeline
    ].freeze

    POST_PROCESSING_TRIGGER_TYPE = %w[
      sbom_ingested
    ].freeze

    REMEDIATION_TRIGGER_TYPES = [
      *POST_PROCESSING_TRIGGER_TYPE,
      *Enums::Security.remediation_scan_profile_trigger_types.keys.map(&:to_s)
    ].freeze

    ALLOWED_TRIGGER_TYPES_BY_SCAN_TYPE = {
      'sast' => PIPELINE_RELATED_TRIGGER_TYPE,
      'dependency_scanning' => PIPELINE_RELATED_TRIGGER_TYPE,
      'secret_detection' => [*PIPELINE_RELATED_TRIGGER_TYPE, 'git_push_event'].freeze,
      'dependency_scanning_post_processing' => POST_PROCESSING_TRIGGER_TYPE,
      'triage_and_remediation' => REMEDIATION_TRIGGER_TYPES,
      # Merge request head pipelines only. Default-branch scans start from Duo Chat or the API;
      # scheduled scan execution policies come later (!257271).
      'business_logic' => %w[merge_request_pipeline].freeze,
      # Default-branch pipelines only: skillguard_scan/v1 dispatches on them, and only
      # default-branch scans reach the Vulnerability Report.
      'skillguard' => %w[default_branch_pipeline].freeze
    }.freeze

    # Secret push protection only checks that the trigger exists, so a custom config would be silently ignored.
    UNCONFIGURABLE_TRIGGER_TYPES_BY_SCAN_TYPE = {
      'secret_detection' => %w[git_push_event].freeze
    }.freeze

    belongs_to :namespace, optional: false
    belongs_to :scan_profile, class_name: 'Security::ScanProfile', foreign_key: :security_scan_profile_id,
      inverse_of: :scan_profile_triggers, optional: false
    belongs_to :configuration, class_name: 'Security::ScanProfiles::Configuration',
      foreign_key: :security_scan_profile_configuration_id, inverse_of: :scan_profile_triggers,
      optional: true, autosave: true

    enum :trigger_type, Enums::Security.scan_profile_trigger_types

    validates :trigger_type, presence: true
    validates :security_scan_profile_id, uniqueness: { scope: :trigger_type }
    validate :trigger_type_compatible_with_profile
    validate :configuration_allowed_for_trigger_type

    scope :with_ci_variables_associations, -> { preload(:scan_profile, :configuration) }
    scope :with_not_deleted_profile, -> { joins(:scan_profile).merge(Security::ScanProfile.not_deleted) }

    def ci_variables
      effective = Security::ScanProfiles::Configuration.effective_for(scan_profile, self)

      Security::ScanProfiles::Configuration::CiVariables.build(scan_profile.scan_type, effective)
    end

    def ci_inputs
      effective = Security::ScanProfiles::Configuration.effective_for(scan_profile, self)

      Security::ScanProfiles::Configuration::CiInputs.build(scan_profile.scan_type, effective)
    end

    private

    def trigger_type_compatible_with_profile
      return unless scan_profile && trigger_type

      allowed = ALLOWED_TRIGGER_TYPES_BY_SCAN_TYPE.fetch(scan_profile.scan_type, [])
      return if allowed.include?(trigger_type)

      errors.add(:trigger_type, format(s_('SecurityScanProfile|is not allowed for %{scan_type} scan profiles'),
        scan_type: scan_profile.scan_type))
    end

    def configuration_allowed_for_trigger_type
      return unless scan_profile && trigger_type
      return if configuration&.configuration.blank?

      unconfigurable = UNCONFIGURABLE_TRIGGER_TYPES_BY_SCAN_TYPE.fetch(scan_profile.scan_type, [])
      return unless unconfigurable.include?(trigger_type)

      errors.add(:base,
        format(s_('SecurityScanProfile|Configuration is not allowed for the %{trigger_type} trigger'),
          trigger_type: trigger_type))
    end
  end
end
