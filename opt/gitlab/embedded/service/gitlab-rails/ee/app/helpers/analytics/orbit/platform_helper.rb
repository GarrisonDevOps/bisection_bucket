# frozen_string_literal: true

module Analytics
  module Orbit
    # The instance state costs a CustomersDot read, so only a page that shows it asks for `instance:`.
    module PlatformHelper
      def orbit_platform(instance: false)
        ::Gitlab::Json.generate(orbit_platform_data(instance: instance))
      end

      private

      def orbit_platform_data(instance:)
        saas = ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        data = { saas: saas }
        data[:instance] = orbit_instance_platform if instance && !saas

        data
      end

      def orbit_instance_platform
        access = ::Analytics::Orbit::Billing.instance_account.access(group: nil, current_user: current_user)

        { state: access.state.to_s.upcase }
      end
    end
  end
end
