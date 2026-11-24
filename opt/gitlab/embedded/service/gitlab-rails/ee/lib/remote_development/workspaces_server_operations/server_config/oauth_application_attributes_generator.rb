# frozen_string_literal: true

module RemoteDevelopment
  module WorkspacesServerOperations
    module ServerConfig
      class OauthApplicationAttributesGenerator
        OAUTH_NAME = "GitLab Workspaces"
        API_EXTERNAL_URL_PATH_SEGMENT = "workspaces"
        OAUTH_REDIRECT_URI_PATH_SEGMENT = "oauth/redirect"
        TRUSTED = true
        CONFIDENTIAL = false

        # @param [Hash] context
        # @return [Hash]
        def self.generate(context)
          context => {
            settings: {
              gitlab_kas_external_url: gitlab_kas_external_url
            }
          }

          api_external_url = URI.parse(gitlab_kas_external_url)
          api_external_url.scheme = api_external_url.scheme.in?(%w[grpcs wss]) ? "https" : "http"
          api_external_url.path = "#{api_external_url.path}/#{API_EXTERNAL_URL_PATH_SEGMENT}"

          redirect_uri = api_external_url.dup
          redirect_uri.path = "#{redirect_uri.path}/#{OAUTH_REDIRECT_URI_PATH_SEGMENT}"

          organization_id = Organizations::Organization.first&.id # rubocop:disable Gitlab/PreventOrganizationFirst -- Instance-level OAuth app for Workspaces infrastructure, following Web IDE pattern.

          attributes = {
            name: OAUTH_NAME,
            redirect_uri: redirect_uri.to_s,
            scopes: "openid",
            trusted: TRUSTED,
            confidential: CONFIDENTIAL,
            organization_id: organization_id
          }

          context.merge(
            api_external_url: api_external_url.to_s,
            oauth_application_attributes: attributes
          )
        end
      end
    end
  end
end
