# frozen_string_literal: true

module RemoteDevelopment
  module WorkspacesServerOperations
    module ServerConfig
      class ValuesExtractor
        # @param [Hash] context
        # @return [Hash]
        def self.extract(context)
          context => {
            api_external_url: String => api_external_url,
            workspaces_oauth_application: workspaces_oauth_application,
          }

          {
            response_payload: {
              api_external_url: api_external_url,
              oauth_client_id: workspaces_oauth_application.uid,
              # NOTE: We are changing the terminology here from `redirect_uri` to `redirect_url` for the external API.
              #       The Doorkeeper API calls it "uri", so we use that internally in the code,
              #       but all the other configuration for KAS and related docs use the term URL.
              oauth_redirect_url: workspaces_oauth_application.redirect_uri
            }
          }
        end
      end
    end
  end
end
