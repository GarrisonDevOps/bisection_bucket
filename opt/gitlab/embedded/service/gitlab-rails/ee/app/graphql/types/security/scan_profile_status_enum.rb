# frozen_string_literal: true

module Types
  module Security
    class ScanProfileStatusEnum < Types::BaseEnum
      graphql_name 'ScanProfileStatus'
      description 'Computed display status for a scan profile.'

      value 'NOT_CONFIGURED', value: 'not_configured',
        description: 'Profile is not applied for the scan type.'
      value 'PENDING', value: 'pending',
        description: 'Profile is attached but no scan has completed yet.'
      value 'ACTIVE', value: 'active',
        description: 'Scans succeeding and not stale.'
      value 'WARNING', value: 'warning',
        description: "Fewer than #{::Security::ScanProfileProjectStatus::FAILED_THRESHOLD} consecutive scan failures."
      value 'FAILED', value: 'failed',
        description: "#{::Security::ScanProfileProjectStatus::FAILED_THRESHOLD}+ consecutive scan failures."
      value 'STALE', value: 'stale',
        description: "No scan activity in #{::Security::ScanProfileProjectStatus::STALE_THRESHOLD_DAYS} days."
    end
  end
end
