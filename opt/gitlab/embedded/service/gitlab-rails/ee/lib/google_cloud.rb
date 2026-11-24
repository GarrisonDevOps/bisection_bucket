# frozen_string_literal: true

module GoogleCloud
  GLGO_BASE_URL = if Gitlab.staging?
                    'https://glgo.staging.runway.gitlab.net'
                  else
                    'https://auth.gcp.gitlab.com'
                  end

  GLGO_TOKEN_ENDPOINT_URL = "#{GLGO_BASE_URL}/token".freeze

  CREDENTIALS_TYPE = 'external_account'
  STS_URL = 'https://sts.googleapis.com/v1/token'
  SUBJECT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:jwt'
  CREDENTIAL_SOURCE_FORMAT = {
    'type' => 'json',
    'subject_token_field_name' => 'token'
  }.freeze

  ApiError = Class.new(StandardError)
  AuthenticationError = Class.new(StandardError)

  def self.glgo_base_url
    GLGO_BASE_URL
  end

  def self.credentials(identity_provider_resource_name:, encoded_jwt:)
    {
      type: CREDENTIALS_TYPE,
      audience: identity_provider_resource_name,
      token_url: STS_URL,
      subject_token_type: SUBJECT_TOKEN_TYPE,
      credential_source: {
        url: GLGO_TOKEN_ENDPOINT_URL,
        headers: { 'Authorization' => "Bearer #{encoded_jwt}" },
        format: CREDENTIAL_SOURCE_FORMAT
      }
    }
  end
end
