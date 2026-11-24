# frozen_string_literal: true

module EE
  module Gitlab
    module RackAttack
      extend ActiveSupport::Concern

      class_methods do
        extend ::Gitlab::Utils::Override

        # Contribute the incident-management throttle as a definition rather than
        # registering it inline in configure_throttles, so it flows through
        # all_throttle_definitions, the single source both Rack::Attack and the
        # Labkit::RateLimit shadow middleware read. This keeps the EE throttle in
        # lock-step across both stacks during the migration.
        override :throttle_definitions
        def throttle_definitions
          super.merge(
            'throttle_incident_management_notification_web' => ::Gitlab::RackAttack::ThrottleDefinition.new(
              EE::Gitlab::Throttle.incident_management_options,
              ->(req) do
                req.path if req.alerts_notify? &&
                  EE::Gitlab::Throttle.settings.throttle_incident_management_notification_enabled
              end
            )
          )
        end
      end
    end
  end
end
