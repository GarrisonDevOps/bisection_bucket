# frozen_string_literal: true

module Types
  module Security
    class ScanProfileAttachModeEnum < BaseEnum
      graphql_name 'SecurityScanProfileAttachMode'
      description 'Attach mode for security scan profiles'

      value 'SET',
        value: :set,
        description: 'Attaches the profile to all target projects and removes other profiles of the same type.'

      value 'REPLACE',
        value: :replace,
        description: 'Replaces existing profiles of the same type, only on projects that already have one.'

      value 'APPEND',
        value: :append,
        description: 'Adds the profile alongside existing profiles of the same type.'

      value 'FILL_PROFILE_GAPS',
        value: :fill_profile_gaps,
        description: 'Attaches the profile only to projects that have no profile of the same type.'

      value 'FILL_SCAN_GAPS',
        value: :fill_scan_gaps,
        description: 'Attaches the profile only to projects that have no profile of the same type ' \
          'and no scan coverage for that type.'
    end
  end
end
