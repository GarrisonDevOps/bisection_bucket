# frozen_string_literal: true

module Organizations
  module Settings
    module ArtifactRegistryHelper
      include ::Organizations::ArtifactRegistryHelper

      def artifact_registry_settings_app_data(organization)
        {
          organization_gid: organization.to_global_id,
          client_base_url: artifact_registry_client_base_url
        }.to_json
      end
    end
  end
end
