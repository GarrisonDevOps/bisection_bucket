# frozen_string_literal: true

module Gitlab
  module Ci
    module GoogleCloud
      class GenerateBuildEnvironmentVariablesService
        def initialize(build)
          @build = build

          @integration = build.project.google_cloud_platform_workload_identity_federation_integration
        end

        def execute
          return [] unless @integration&.active

          config_json = ::GoogleCloud.credentials(
            identity_provider_resource_name: @integration.identity_provider_resource_name,
            encoded_jwt: encoded_jwt
          ).to_json
          var_attributes = { value: config_json, public: false, masked: true, file: true }

          [
            { key: 'CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE', **var_attributes },
            { key: 'GOOGLE_APPLICATION_CREDENTIALS', **var_attributes }
          ]
        end

        private

        def encoded_jwt
          sub_components = @build.project.ci_id_token_sub_claim_components.map(&:to_sym)

          JwtV2.for_build(
            @build,
            aud: ::GoogleCloud::GLGO_BASE_URL,
            sub_components: sub_components,
            target_audience: @integration.identity_provider_resource_name
          )
        end
      end
    end
  end
end
