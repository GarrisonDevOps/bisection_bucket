# frozen_string_literal: true

module EE
  module API
    module Helpers
      module IntegrationsHelpers
        extend ActiveSupport::Concern

        class_methods do
          extend ::Gitlab::Utils::Override

          override :integrations
          def integrations
            super.merge(
              'github' => ::Integrations::Github.api_arguments,
              'git-guardian' => ::Integrations::GitGuardian.api_arguments,
              'google-cloud-platform-artifact-registry' =>
                ::Integrations::GoogleCloudPlatform::ArtifactRegistry.api_arguments,
              'google-cloud-platform-workload-identity-federation' =>
                ::Integrations::GoogleCloudPlatform::WorkloadIdentityFederation.api_arguments
            )
          end

          override :integration_tier
          def integration_tier(slug)
            slug == 'github' ? :premium : super
          end

          override :integration_classes
          def integration_classes
            [
              ::Integrations::Github,
              ::Integrations::GitGuardian,
              ::Integrations::GoogleCloudPlatform::ArtifactRegistry,
              ::Integrations::GoogleCloudPlatform::WorkloadIdentityFederation,
              *super
            ]
          end

          override :chat_notification_channels
          def chat_notification_channels
            [
              *super,
              {
                required: false,
                name: :vulnerability_channel,
                type: String,
                desc: 'The name of the channel to receive vulnerability_events notifications'
              }
            ].freeze
          end
        end
      end
    end
  end
end
