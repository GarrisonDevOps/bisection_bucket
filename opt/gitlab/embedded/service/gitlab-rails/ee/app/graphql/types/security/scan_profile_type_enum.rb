# frozen_string_literal: true

module Types
  module Security
    class ScanProfileTypeEnum < BaseEnum
      graphql_name 'SecurityScanProfileType'
      description 'Scan profile type'

      Enums::Security.scan_profile_types.except(:business_logic, :skillguard).each_key do |name|
        value(
          name.to_s.upcase,
          value: name.to_s,
          description: name.to_s.humanize
        )
      end

      Enums::Security.remediation_scan_profile_types.except(:triage_and_remediation).each_key do |name|
        value(
          name.to_s.upcase,
          value: name.to_s,
          description: "#{name.to_s.humanize}.",
          experiment: { milestone: '19.2' }
        )
      end

      value 'TRIAGE_AND_REMEDIATION',
        value: 'triage_and_remediation',
        description: 'Triage and remediation.',
        experiment: { milestone: '19.4' }

      value 'BUSINESS_LOGIC',
        value: 'business_logic',
        description: 'Business logic. Available only when the Experiment and beta features setting ' \
          'and the `bl_security_analyzer` feature flag are enabled for the top-level group. ' \
          'On GitLab Self-Managed, GitLab must also enable it for the instance. On GitLab ' \
          'Dedicated, GitLab enabling it for the instance replaces the feature flag. ' \
          'Otherwise, scan profiles are hidden and cannot be created or updated.'

      value 'SKILLGUARD',
        value: 'skillguard',
        description: 'SkillGuard.',
        experiment: { milestone: '19.6' }
    end
  end
end
