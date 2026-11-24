# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class DuoCoreFeaturesEnabledMetric < GenericMetric
          def value
            # Service Ping is instance-scoped: read the legacy instance-wide
            # settings row, which belongs to the default organization.
            organization = ::Organizations::Organization.default_organization # rubocop:disable Gitlab/AvoidDefaultOrganization -- Service Ping reports instance-level values
            return unless organization

            ::Ai::Setting.for_organization_read_only(organization).duo_core_features_enabled
          end
        end
      end
    end
  end
end
