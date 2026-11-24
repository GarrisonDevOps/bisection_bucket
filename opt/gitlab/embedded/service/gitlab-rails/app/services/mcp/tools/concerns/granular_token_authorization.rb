# frozen_string_literal: true

module Mcp
  module Tools
    module Concerns
      module GranularTokenAuthorization
        private

        # Tools read as the token's user, so a token that only the public access rule admits
        # is denied unless the tool passes `allow_public_access: true` (see the service).
        def authorize_granular_token!(resource, permissions, not_found_message:, allow_public_access: false)
          raise ::Mcp::Tools::Concerns::ResourceFinder::ResourceForbiddenError, not_found_message if access_token.nil?

          response = ::Authz::Tokens::AuthorizeGranularScopesService.new(
            boundaries: ::Authz::Boundary.for(resource),
            permissions: permissions,
            token: access_token,
            allow_public_access: allow_public_access
          ).execute
          return if response.success?

          if response.reason == :resource_not_found
            raise ::Mcp::Tools::Concerns::ResourceFinder::ResourceNotFoundError, not_found_message
          end

          ::Current.add_granular_denied_permissions(response.payload[:denied_permissions])
          raise ::Mcp::Tools::Concerns::ResourceFinder::ResourceForbiddenError, response.message
        end
      end
    end
  end
end
