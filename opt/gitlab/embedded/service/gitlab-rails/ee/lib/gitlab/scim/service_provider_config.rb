# frozen_string_literal: true

module Gitlab
  module Scim
    # SCIM service provider configuration (RFC 7643 Section 5).
    # Advertises only the SCIM features GitLab currently supports.
    module ServiceProviderConfig
      SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'

      class << self
        def to_h(context:)
          {
            schemas: [SCHEMA],
            documentationUri: documentation_uri(context),
            patch: { supported: true },
            bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
            filter: { supported: true, maxResults: Kaminari.config.max_per_page },
            changePassword: { supported: false },
            sort: { supported: false },
            etag: { supported: false },
            authenticationSchemes: [
              {
                type: 'oauthbearertoken',
                name: 'OAuth Bearer Token',
                description: 'Authentication with a GitLab SCIM token sent as a bearer token.',
                primary: true
              }
            ]
          }
        end

        private

        def documentation_uri(context)
          url_helpers = Gitlab::Routing.url_helpers

          case context
          when :group
            url_helpers.help_page_url('user/group/saml_sso/scim_setup.md')
          when :instance
            url_helpers.help_page_url('administration/settings/scim_setup.md')
          else
            raise ArgumentError, "Unknown SCIM context: #{context}"
          end
        end
      end
    end
  end
end
