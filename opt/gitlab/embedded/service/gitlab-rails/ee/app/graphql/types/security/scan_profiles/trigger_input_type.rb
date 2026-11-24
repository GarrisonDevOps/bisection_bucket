# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      class TriggerInputType < BaseInputObject
        graphql_name 'SecurityScanProfileTriggerInput'
        description 'A trigger, with optional configuration, for a scan profile.'

        argument :trigger_type, ::Types::Security::ScanProfileTriggerTypeEnum,
          required: true,
          description: 'Type of the trigger.'

        argument :configuration, ::Types::Security::ScanProfiles::ConfigurationInputType,
          required: false,
          experiment: { milestone: '19.3' },
          description: 'Configuration attached to the trigger. When set, exactly one member must be present ' \
            'and it must match the scan profile type.'
      end
    end
  end
end
