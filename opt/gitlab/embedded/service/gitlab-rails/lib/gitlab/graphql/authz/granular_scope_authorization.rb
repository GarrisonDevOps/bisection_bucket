# frozen_string_literal: true

module Gitlab
  module Graphql
    module Authz
      class GranularScopeAuthorization
        GRANULAR_TOKENS_AUTHZ_CACHE_KEY = :granular_tokens_authz_cache
        TOKEN_USER_KEY = :granular_token_user

        attr_reader :directives

        delegate :empty?, :any?, to: :directives

        # `permissions:` replaces the permissions of the directives, which then only
        # locate the boundary.
        def initialize(directives, permissions: nil)
          @directives = directives.select { |directive| directive.is_a?(::Directives::Authz::GranularScope) }
          @permissions = Array(permissions).map(&:to_s).sort if permissions
        end

        # Also scopes `context[:current_user]` for the current path and everything below it:
        # nil when only the public access rule of Authz::BoundaryPolicy admitted the token,
        # back to the token's user when the token holds the permissions itself.
        def ok?(object, context, arguments: nil)
          authorized, _message, public_access = authorized?(object, context, arguments)
          scope_current_user(context, public_access) if authorized
          authorized
        end

        def authorize!(object, context, arguments: nil)
          authorized, message, public_access = authorized?(object, context, arguments)
          raise ::Gitlab::Graphql::Errors::ArgumentError, message unless authorized && !public_access

          scope_current_user(context, false)
        end

        private

        def scope_current_user(context, public_access)
          return if public_access.nil?

          if public_access
            context[TOKEN_USER_KEY] = context[:current_user] unless context.key?(TOKEN_USER_KEY)
            context.scoped_set!(:current_user, nil)
          elsif context.key?(TOKEN_USER_KEY)
            context.scoped_set!(:current_user, context[TOKEN_USER_KEY])
          end
        end

        def skip_authorization?
          directives.any? { |directive| directive.arguments[:skip_reason].present? }
        end

        def permissions
          @permissions ||= directives.first.arguments.fetch(:permissions, []).sort
        end

        def authorized?(object, context, arguments)
          token = context[:access_token]
          return success unless token && token.respond_to?(:granular?)
          return success unless token.subject_to_granular_authorization?

          # If both object and arguments are nil,
          # there is no source a boundary can be extracted from.
          return success if object.nil? && arguments.nil?
          return success if skip_authorization?

          # if no gPAT directives are defined, granular tokens deny access while
          # legacy tokens fall through to their existing authorization
          if directives.empty?
            return error(default_error_message) if token.granular?

            return success
          end

          boundary_objects = boundary_extractor(object, arguments).extract
          key = cache_key(boundary_objects)

          fetch_cached(context, key) do
            # A request only the public access rule admits resolves as anonymous (scope_current_user).
            response = ::Authz::Tokens::AuthorizeGranularScopesService.new(
              boundaries: boundary_objects.map { |resource| ::Authz::Boundary.for(resource) },
              permissions: permissions,
              token: context[:access_token],
              allow_public_access: true
            ).execute

            if response.success?
              [true, response.message, response.payload[:public_access] || false]
            else
              ::Current.add_granular_denied_permissions(response.payload[:denied_permissions])
              error(response.message)
            end
          end
        end

        def boundary_extractor(object, arguments)
          BoundaryExtractor.new(directives, object: object, arguments: arguments)
        end

        def fetch_cached(context, key)
          cache = context[GRANULAR_TOKENS_AUTHZ_CACHE_KEY] ||= {}
          return cache[key] if cache.key?(key)

          cache[key] = yield
        end

        def cache_key(boundary_objects)
          [
            permissions,
            boundary_objects.map { |boundary| cache_identifier_for(boundary) }.sort_by(&:to_s)
          ]
        end

        def cache_identifier_for(boundary_object)
          return boundary_object if boundary_object.is_a?(Symbol)

          [boundary_object.class.name, boundary_object.id]
        end

        def success
          [true, nil]
        end

        def error(message)
          [false, message]
        end

        def default_error_message
          ::Gitlab::Graphql::Authorize::AuthorizeResource::RESOURCE_ACCESS_ERROR
        end
      end
    end
  end
end
