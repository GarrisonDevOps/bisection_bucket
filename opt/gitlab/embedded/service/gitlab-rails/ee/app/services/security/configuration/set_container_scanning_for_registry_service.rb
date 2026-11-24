# frozen_string_literal: true

module Security
  module Configuration
    class SetContainerScanningForRegistryService
      def self.execute(namespace:, enable:)
        # At present, the security_setting feature is exclusively accessible for projects.
        # Following the resolution of https://gitlab.com/gitlab-org/gitlab/-/issues/451430,
        # this feature will also be available at the group level.
        ServiceResponse.success(
          payload: {
            enabled: namespace.security_setting.set_container_scanning_for_registry!(
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
