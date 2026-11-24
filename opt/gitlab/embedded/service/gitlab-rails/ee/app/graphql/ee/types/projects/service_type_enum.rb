# frozen_string_literal: true

module EE
  module Types
    module Projects
      module ServiceTypeEnum
        extend ActiveSupport::Concern

        # This list is only used for GraphQL documentation purposes, to be able to
        # append (SaaS only) to the ServiceType enum description.
        SAAS_ONLY_INTEGRATION_NAMES = [
          ::Integrations::GoogleCloudPlatform::WorkloadIdentityFederation.to_param,
          ::Integrations::GoogleCloudPlatform::ArtifactRegistry.to_param
        ].freeze

        class_methods do
          extend ::Gitlab::Utils::Override

          private

          override :integration_names
          def integration_names
            Integration.available_integration_names(
              include_instance_specific: false,
              include_dev: false,
              include_disabled: true,
              include_blocked_by_settings: true
            )
          end

          override :value_description
          def value_description(name)
            description = super
            description += " (SaaS only)" if name.in?(SAAS_ONLY_INTEGRATION_NAMES)
            description
          end
        end
      end
    end
  end
end
