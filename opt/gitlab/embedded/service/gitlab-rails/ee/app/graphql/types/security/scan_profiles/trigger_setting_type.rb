# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      # rubocop:disable Graphql/AuthorizeTypes -- Authorization occurs at parent level (ScanProfileType)
      class TriggerSettingType < BaseObject
        graphql_name 'ScanProfileTriggerSetting'
        description 'A scan profile trigger and its effective configuration.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :trigger_type, ::Types::Security::ScanProfileTriggerTypeEnum,
          null: false,
          description: 'Type of the trigger.'

        field :configuration, ::Types::Security::ScanProfiles::ConfigurationType,
          null: true,
          description: 'Effective configuration for the trigger. Null for scan types without a typed configuration.'

        def configuration
          # ScanProfileConfiguration is a union. Return the trigger only when its scan type maps to a
          # member type (see ConfigurationType.resolve_type); otherwise return nil so the field is
          # null. Handing the union a value it cannot resolve makes graphql-ruby raise, not return null.
          object if ::Types::Security::ScanProfiles::ConfigurationType.resolve_type(object, context)
        end
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
