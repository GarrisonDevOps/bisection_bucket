# frozen_string_literal: true

module GoogleCloud
  class BaseClient
    CLOUD_PLATFORM_SCOPE = 'https://www.googleapis.com/auth/cloud-platform'

    GOOGLE_CLOUD_SUBJECT_TOKEN_ERROR_MESSAGE = 'Unable to retrieve glgo token'
    GOOGLE_CLOUD_TOKEN_EXCHANGE_ERROR_MESSAGE = 'Token exchange failed'

    SAAS_ONLY_ERROR_MESSAGE = "This is a SaaS-only feature that can't run here"
    BLANK_PARAMETERS_ERROR_MESSAGE = 'All Google Cloud parameters are required'
    WRONG_INTEGRATION_CLASS = 'WLIF integration must be an instance of' \
                              "#{Integrations::GoogleCloudPlatform::WorkloadIdentityFederation.name}".freeze
    DISABLED_INTEGRATION = 'WLIF integration is not activated'

    # Initialize and build a new Compute client.
    # This will use glgo and a workload identity federation instance to exchange
    # a JWT from GitLab for an access token to be used with the Google Cloud API.
    #
    # +wlif_integration+ The project integration that contains project id and the identity provider resource name.
    #                    Must be an instance of Integrations::GoogleCloudPlatform::WorkloadIdentityFederation.
    # +user+ The User instance.
    #
    # All parameters are required.
    #
    # Possible exceptions:
    #
    # +ArgumentError+ if one or more of the parameters is blank.
    # +RuntimeError+ if this is used outside the SaaS instance.
    def initialize(wlif_integration:, user:, params: {})
      raise SAAS_ONLY_ERROR_MESSAGE unless Gitlab::Saas.feature_available?(:google_cloud_support)
      raise ArgumentError, BLANK_PARAMETERS_ERROR_MESSAGE if wlif_integration.blank? || user.blank?

      unless wlif_integration.is_a?(::Integrations::GoogleCloudPlatform::WorkloadIdentityFederation)
        raise ArgumentError, WRONG_INTEGRATION_CLASS
      end

      raise ArgumentError, DISABLED_INTEGRATION unless wlif_integration.activated?

      @wlif_integration = wlif_integration
      @user = user
      @params = params
    end

    private

    attr_reader :wlif_integration, :user, :params

    delegate :identity_provider_resource_name, to: :wlif_integration, prefix: :google_cloud

    def credentials
      ::GoogleCloud.credentials(
        identity_provider_resource_name: google_cloud_identity_provider_resource_name,
        encoded_jwt: encoded_jwt
      )
    end

    def encoded_jwt
      jwt = ::GoogleCloud::Jwt.new(
        project: project,
        user: user,
        claims: {
          audience: GLGO_BASE_URL,
          target_audience: google_cloud_identity_provider_resource_name
        }
      )
      jwt.encoded
    end

    def google_cloud_project_id
      wlif_integration.workload_identity_federation_project_id
    end

    def project
      wlif_integration.project
    end

    def handling_errors
      yield
    rescue RuntimeError => e
      if e.message.include?(GOOGLE_CLOUD_SUBJECT_TOKEN_ERROR_MESSAGE) ||
          e.message.include?(GOOGLE_CLOUD_TOKEN_EXCHANGE_ERROR_MESSAGE)
        raise ::GoogleCloud::AuthenticationError, e.message
      end

      raise
    rescue ::Google::Cloud::Error => e
      raise ::GoogleCloud::ApiError, e.message
    end
  end
end
