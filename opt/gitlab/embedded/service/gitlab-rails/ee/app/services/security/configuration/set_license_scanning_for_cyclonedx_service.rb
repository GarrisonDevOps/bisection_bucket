# frozen_string_literal: true

module Security
  module Configuration
    class SetLicenseScanningForCyclonedxService
      def self.execute(namespace:, enable:)
        ServiceResponse.success(
          payload: {
            enabled: namespace.security_setting.set_license_scanning_for_cyclonedx!(
              enabled: enable
            ),
            errors: []
          })
      rescue StandardError => e
        ServiceResponse.error(
          message: e.message,
          payload: { enabled: nil }
        )
      end
    end
  end
end
