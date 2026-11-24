# frozen_string_literal: true

module Types
  module Security
    class ScanProfileTriggerTypeEnum < BaseEnum
      graphql_name 'ScanProfileTriggerType'
      description 'Scan profile trigger type'

      Enums::Security.scan_profile_trigger_types
        .except(:sbom_ingested, *Enums::Security.remediation_scan_profile_trigger_types.keys)
        .each_key do |name|
        value(
          name.to_s.upcase,
          value: name.to_s,
          description: name.to_s.humanize
        )
      end

      value 'SBOM_INGESTED',
        value: 'sbom_ingested',
        description: 'SBOM ingested.',
        experiment: { milestone: '19.2' }

      Enums::Security.remediation_scan_profile_trigger_types.each_key do |name|
        description = name.to_s.humanize.sub(/\ASast\b/, 'SAST')

        value(
          name.to_s.upcase,
          value: name.to_s,
          description: "#{description}.",
          experiment: { milestone: '19.4' }
        )
      end
    end
  end
end
