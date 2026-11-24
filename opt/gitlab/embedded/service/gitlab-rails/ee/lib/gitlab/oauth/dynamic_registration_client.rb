# frozen_string_literal: true

module Gitlab
  module Oauth
    # Service for OAuth 2.0 Dynamic Client Registration (RFC 7591)
    # and OAuth 2.0 Authorization Server Metadata discovery (RFC 8414)
    #
    # This service handles:
    # - Discovery of OAuth authorization server metadata via .well-known endpoints
    # - Dynamic client registration with OAuth providers
    # - Building OAuth authorization URLs
    #
    # @example Basic usage
    #   service = Gitlab::Oauth::DynamicRegistrationClient.new(
    #     server_url: 'https://example.com/mcp',
    #     client_name: 'GitLab Integration',
    #     redirect_uris: ['https://gitlab.com/oauth/callback']
    #   )
    #
    #   # Discover OAuth server metadata
    #   metadata = service.discover_metadata
    #
    #   # Register a new OAuth client
    #   result = service.register_client
    #   client_id = result[:client_id]
    #   client_secret = result[:client_secret]
    #
    class DynamicRegistrationClient
      include Gitlab::Utils::StrongMemoize

      DiscoveryError = Class.new(StandardError)
      RegistrationError = Class.new(StandardError)
      # Raised when the registration endpoint requires authorization (HTTP 401/403).
      # RFC 7591 3.1 allows servers to protect their registration endpoint with an
      # initial access token. In this case, clients must be pre-registered manually.
      ProtectedRegistrationError = Class.new(RegistrationError)

      DEFAULT_GRANT_TYPES = %w[authorization_code refresh_token].freeze
      DEFAULT_RESPONSE_TYPES = %w[code].freeze
      REQUEST_TIMEOUT = 5

      def self.token_endpoint_auth_scheme(metadata)
        methods = Array(metadata['token_endpoint_auth_methods_supported'])

        if methods.include?('client_secret_post') && methods.exclude?('client_secret_basic')
          :request_body
        else
          :basic_auth
        end
      end

      # Initialize the dynamic registration service
      #
      # @param server_url [String] The base URL of the resource server
      # @param client_name [String] Human-readable name for the OAuth client
      # @param redirect_uris [Array<String>] List of allowed redirect URIs
      # @param grant_types [Array<String>] OAuth grant types to request
      # @param response_types [Array<String>] OAuth response types to request
      # @param scope [String, nil] Space-separated list of OAuth scopes. When nil, scopes advertised
      #   by the server metadata are used during registration. Omitted entirely if none are available.
      # @param token_endpoint_auth_method [String] Client authentication method
      def initialize(
        server_url:, client_name:, redirect_uris:, grant_types: nil, response_types: nil,
        scope: nil, token_endpoint_auth_method: nil)
        @server_url = server_url
        @client_name = client_name
        @redirect_uris = Array(redirect_uris)
        @grant_types = grant_types || DEFAULT_GRANT_TYPES
        @response_types = response_types || DEFAULT_RESPONSE_TYPES
        @scope = scope
        @token_endpoint_auth_method = token_endpoint_auth_method
      end

      # Discover the protected resource metadata (RFC 9728)
      #
      # The well-known URL is constructed by inserting /.well-known/oauth-protected-resource
      # between the host and path components of the resource identifier (RFC 9728 Section 3.1).
      # When that fails, the root well-known URL is tried, as the MCP authorization spec requires.
      # Returns nil when neither endpoint is available or the responses fail validation.
      #
      # @return [Hash, nil] The protected resource metadata, or nil if unavailable/invalid
      # @raise [DiscoveryError] If the server URL is invalid
      def discover_resource_metadata
        uri = parse_server_url
        base_url = build_base_url(uri)
        path_metadata_url = build_protected_resource_metadata_url(uri)
        root_metadata_url = build_protected_resource_metadata_url(URI.parse(base_url))

        metadata = fetch_resource_metadata(path_metadata_url, resources: [server_url])
        return metadata if metadata || root_metadata_url == path_metadata_url

        fetch_resource_metadata(root_metadata_url, resources: [base_url, server_url])
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e)
        raise DiscoveryError, format(_('Failed to discover resource metadata: %{error}'), error: e.message)
      end
      strong_memoize_attr :discover_resource_metadata

      # Discover the OAuth authorization server URL
      # Implements RFC 9728: OAuth 2.0 Protected Resource Metadata
      #
      # @return [String] The authorization server URL
      # @raise [DiscoveryError] If the server URL is invalid
      def discover_auth_server_url
        resource_metadata = discover_resource_metadata
        return build_base_url(parse_server_url) unless resource_metadata

        resource_metadata['authorization_servers'].first
      rescue DiscoveryError
        raise
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e)
        raise DiscoveryError, format(_('Failed to discover authorization server: %{error}'), error: e.message)
      end
      strong_memoize_attr :discover_auth_server_url

      # Discover OAuth authorization server metadata
      # Implements RFC 8414: OAuth 2.0 Authorization Server Metadata
      #
      # @param auth_server_url [String, nil] Authorization server URL (will auto-discover if nil)
      # @return [Hash] The authorization server metadata
      # @raise [DiscoveryError] If metadata discovery fails
      def discover_metadata(auth_server_url = nil)
        auth_server_url ||= discover_auth_server_url
        metadata_url = build_authorization_server_metadata_url(auth_server_url)

        validate_url!(metadata_url)
        response = Gitlab::HTTP.get(metadata_url, timeout: REQUEST_TIMEOUT)

        raise DiscoveryError, _('Failed to discover OAuth metadata') unless response.success?

        response.parsed_response
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e)
        raise DiscoveryError, format(_('Failed to discover OAuth metadata: %{error}'), error: e.message)
      end

      # Register a new OAuth client with the authorization server
      # Implements RFC 7591: OAuth 2.0 Dynamic Client Registration Protocol
      #
      # @param metadata [Hash, nil] Authorization server metadata (will auto-discover if nil)
      # @return [Hash] Registration response with :client_id and :client_secret
      # @raise [ProtectedRegistrationError] If the registration endpoint requires an initial access token (HTTP 401/403)
      # @raise [RegistrationError] If registration fails or is not supported
      def register_client(metadata = nil)
        metadata ||= discover_metadata
        registration_endpoint = metadata['registration_endpoint']

        unless registration_endpoint
          raise RegistrationError,
            _('Dynamic client registration not supported by this server')
        end

        registration_payload = build_registration_payload(metadata)

        validate_url!(registration_endpoint)
        response = Gitlab::HTTP.post(
          registration_endpoint,
          body: registration_payload.to_json,
          headers: { 'Content-Type' => 'application/json' },
          timeout: REQUEST_TIMEOUT
        )

        if response.code == 401 || response.code == 403
          raise ProtectedRegistrationError,
            _('Dynamic client registration requires authorization. ' \
              'Please pre-register the OAuth client and configure the client ID manually.')
        end

        unless response.success?
          raise RegistrationError,
            format(_('Client registration failed: %{error}'), error: response.body)
        end

        parse_registration_response(response.parsed_response)
      rescue DiscoveryError => e
        raise RegistrationError, format(_('Cannot register client: %{error}'), error: e.message)
      rescue RegistrationError
        raise
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e)
        raise RegistrationError, format(_('Client registration failed: %{error}'), error: e.message)
      end

      # Generate a PKCE code_verifier / code_challenge pair (RFC 7636).
      #
      # @return [Hash] with :code_verifier (keep secret, send at token exchange)
      #   and :code_challenge (send in the authorization URL)
      def generate_pkce
        verifier = SecureRandom.urlsafe_base64(32)
        challenge = Base64.urlsafe_encode64(
          OpenSSL::Digest::SHA256.digest(verifier),
          padding: false
        )
        { code_verifier: verifier, code_challenge: challenge }
      end

      # Build an OAuth authorization URL
      #
      # @param authorization_endpoint [String] The authorization endpoint URL
      # @param client_id [String] The OAuth client ID
      # @param redirect_uri [String] The redirect URI for this authorization request
      # @param state [String] The state parameter for CSRF protection
      # @param scope [String, nil] Custom scope (uses default if nil)
      # @param code_challenge [String, nil] PKCE code challenge (RFC 7636 S256)
      # @param issuer [String, nil] Issuer identifier from the discovered server metadata.
      #   When provided, used as the primary signal for provider detection (e.g. Google).
      #   Falls back to inspecting the authorization endpoint host when nil.
      # @return [String] The complete authorization URL
      def build_authorization_url(
        authorization_endpoint:, client_id:, redirect_uri:, state:,
        scope: nil, code_challenge: nil, issuer: nil)
        uri = URI.parse(authorization_endpoint)
        google = google_provider?(issuer: issuer, authorization_endpoint_uri: uri)

        query_params = {
          client_id: client_id,
          redirect_uri: redirect_uri,
          response_type: 'code',
          state: state,
          scope: scope || @scope,
          prompt: 'consent'
        }

        # Google does not support the standard offline_access scope.
        # Instead it requires access_type=offline to obtain a refresh token.
        query_params[:access_type] = 'offline' if google

        if code_challenge
          query_params[:code_challenge] = code_challenge
          query_params[:code_challenge_method] = 'S256'
        end

        uri.query = URI.encode_www_form(query_params)
        uri.to_s
      end

      private

      attr_reader :server_url, :client_name, :redirect_uris, :grant_types,
        :response_types, :scope, :token_endpoint_auth_method

      def validate_url!(url)
        Gitlab::HTTP_V2::UrlBlocker.validate!(
          url,
          schemes: %w[http https],
          enforce_sanitization: true,
          allow_localhost: Gitlab::CurrentSettings.allow_local_requests_from_web_hooks_and_services?,
          allow_local_network: Gitlab::CurrentSettings.allow_local_requests_from_web_hooks_and_services?,
          deny_all_requests_except_allowed: Gitlab::CurrentSettings.deny_all_requests_except_allowed?,
          outbound_local_requests_allowlist: Gitlab::CurrentSettings.outbound_local_requests_whitelist # rubocop:disable Naming/InclusiveLanguage -- existing setting name
        )
      rescue Gitlab::HTTP_V2::UrlBlocker::BlockedUrlError => e
        raise DiscoveryError, format(_('Blocked URL: %{error}'), error: e.message)
      end

      def parse_server_url
        URI.parse(server_url)
      rescue URI::InvalidURIError => e
        raise DiscoveryError, format(_('Invalid server URL: %{error}'), error: e.message)
      end

      def build_base_url(uri)
        port_part = uri.port && [80, 443].exclude?(uri.port) ? ":#{uri.port}" : ''
        "#{uri.scheme}://#{uri.host}#{port_part}"
      end

      # Constructs the authorization server metadata URL per RFC 8414 Section 3.1:
      # insert /.well-known/oauth-authorization-server between the host and path.
      # e.g. https://auth.example.com/tenant1 -> https://auth.example.com/.well-known/oauth-authorization-server/tenant1
      def build_authorization_server_metadata_url(auth_server_url)
        build_well_known_url(URI.parse(auth_server_url), 'oauth-authorization-server')
      rescue URI::InvalidURIError => e
        raise DiscoveryError, format(_('Invalid authorization server URL: %{error}'), error: e.message)
      end

      # Constructs the protected resource metadata URL per RFC 9728 Section 3.1:
      # insert /.well-known/oauth-protected-resource between the host and path.
      # e.g. https://mcp.example.com/mcp -> https://mcp.example.com/.well-known/oauth-protected-resource/mcp
      def build_protected_resource_metadata_url(uri)
        build_well_known_url(uri, 'oauth-protected-resource')
      end

      # Shared RFC 8414/9728 Section 3.1 well-known URL construction: insert
      # /.well-known/<well_known_path> between the host and any existing path.
      def build_well_known_url(uri, well_known_path)
        well_known_url = Gitlab::Utils.append_path(build_base_url(uri), ".well-known/#{well_known_path}")
        path = uri.path.to_s.delete_prefix('/').delete_suffix('/')

        return well_known_url if path.empty?

        Gitlab::Utils.append_path(well_known_url, path)
      end

      def fetch_resource_metadata(metadata_url, resources:)
        validate_url!(metadata_url)
        response = Gitlab::HTTP.get(metadata_url, timeout: REQUEST_TIMEOUT)
        parsed = response.parsed_response

        parsed if response.success? && valid_resource_metadata?(parsed, resources)
      end

      # Validates the resource metadata response per RFC 9728 Section 3.3: the 'resource' field must match
      # one of the accepted resource identifiers, and authorization_servers must be present.
      # Root metadata may name the bare host or the full server URL, so both are accepted there.
      def valid_resource_metadata?(parsed, resources)
        return false unless parsed['authorization_servers']&.any?

        resource = parsed['resource'].to_s.delete_suffix('/')
        resources.any? { |accepted| accepted.delete_suffix('/') == resource }
      end

      def build_registration_payload(metadata = {})
        # Prefer scopes advertised by the server; fall back to caller-supplied or default
        server_scopes = metadata['scopes_supported']&.join(' ')
        effective_scope = scope || server_scopes

        payload = {
          client_name: client_name,
          redirect_uris: redirect_uris,
          grant_types: grant_types,
          response_types: response_types,
          token_endpoint_auth_method: token_endpoint_auth_method || registration_auth_method(metadata)
        }
        payload[:scope] = effective_scope if effective_scope.present?
        payload
      end

      def registration_auth_method(metadata)
        if self.class.token_endpoint_auth_scheme(metadata) == :request_body
          'client_secret_post'
        else
          'client_secret_basic'
        end
      end

      def parse_registration_response(response)
        {
          client_id: response['client_id'],
          client_secret: response['client_secret'],
          registration_data: response
        }
      end

      # Returns true when the OAuth provider is Google.
      # Google does not honour the standard offline_access scope and instead
      # requires the access_type=offline extension parameter.
      #
      # Detection strategy (most-to-least authoritative):
      # 1. Issuer from discovered server metadata -- Google's issuer is
      #    "https://accounts.google.com" (canonical) or "accounts.google.com"
      #    (legacy, schemeless form documented by Google for ID token validation).
      # 2. Host of the authorization endpoint URI -- Google's single authorization
      #    host is accounts.google.com (no regional variants exist).
      #
      # @param issuer [String, nil]
      # @param authorization_endpoint_uri [URI]
      def google_provider?(issuer:, authorization_endpoint_uri:)
        return google_issuer?(issuer) unless issuer.nil?

        authorization_endpoint_uri.host == 'accounts.google.com'
      end

      GOOGLE_ISSUERS = %w[https://accounts.google.com accounts.google.com].freeze
      private_constant :GOOGLE_ISSUERS

      def google_issuer?(issuer)
        GOOGLE_ISSUERS.include?(issuer)
      end
    end
  end
end
