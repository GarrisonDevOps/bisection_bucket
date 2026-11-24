# frozen_string_literal: true

module EE
  module ServicePing
    module ServicePingSettings
      extend ::Gitlab::Utils::Override

      override :license_operational_metric_enabled?
      def license_operational_metric_enabled?
        return false if ::License.current&.offline_cloud_license?

        ::License.current&.customer_service_enabled? || super
      end
    end
  end
end
