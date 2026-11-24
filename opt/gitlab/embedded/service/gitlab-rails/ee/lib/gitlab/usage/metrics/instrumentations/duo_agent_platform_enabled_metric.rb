# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class DuoAgentPlatformEnabledMetric < GenericMetric
          value do
            # Service Ping is instance-scoped: read the legacy instance-wide
            # settings row, which belongs to the default organization.
            organization = ::Organizations::Organization.default_organization # rubocop:disable Gitlab/AvoidDefaultOrganization -- Service Ping reports instance-level values

            ::Ai::Setting.for_organization_read_only(organization).duo_agent_platform_enabled if organization
          end
        end
      end
    end
  end
end
