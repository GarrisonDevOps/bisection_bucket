# frozen_string_literal: true

module EE
  module Gitlab
    module RateLimit
      module RequestClassification
        extend ::Gitlab::Utils::Override

        VIRTUAL_REGISTRIES_API_PACKAGE_TYPES = ::VirtualRegistries::PACKAGE_TYPES.map(&:to_s).join('|')
        VIRTUAL_REGISTRIES_API_PACKAGES_ENDPOINTS_REGEX =
          %r{^/api/v\d+/virtual_registries/packages/(?:#{VIRTUAL_REGISTRIES_API_PACKAGE_TYPES})/\d+/}
        VIRTUAL_REGISTRIES_API_CONTAINER_ENDPOINTS_REGEX =
          %r{^/v2/virtual_registries/container/\d+/}
        # The two endpoints as one regex, so the Labkit shadow can union it into its
        # skip path matcher (see EE::...::LabkitRateLimit::ThrottleRegistry#skip_path_regex).
        VIRTUAL_REGISTRIES_API_ENDPOINTS_REGEX = ::Regexp.union(
          VIRTUAL_REGISTRIES_API_PACKAGES_ENDPOINTS_REGEX,
          VIRTUAL_REGISTRIES_API_CONTAINER_ENDPOINTS_REGEX
        )
        GEO_PROXY_API_PATH_REGEX = %r{^/api/v\d+/geo/proxy\z}
        # The dedicated Cloud Connector JWKS (ee/app/controllers/cloud_connector/keys_controller.rb)
        # is an unauthenticated, machine-to-machine metadata endpoint, like /oauth/discovery/keys.
        # Classify it as an API request so it is throttled in the same unauthenticated API bucket
        # rather than the unauthenticated web bucket its `/-/` path would otherwise fall into.
        CLOUD_CONNECTOR_KEYS_PATH_REGEX = %r{^/-/cloud_connector/keys\z}

        override :api_request?
        def api_request?
          super || matches?(CLOUD_CONNECTOR_KEYS_PATH_REGEX)
        end

        def geo?
          if env['HTTP_AUTHORIZATION']
            ::Gitlab::Geo::JwtRequestDecoder.geo_auth_attempt?(env['HTTP_AUTHORIZATION'])
          else
            false
          end
        end

        def verified_geo_request?
          return false unless geo?

          decoder = ::Gitlab::Geo::JwtRequestDecoder.new(env['HTTP_AUTHORIZATION'])
          decoder.decode.present?
        rescue StandardError
          false
        end

        def virtual_registries_api_endpoints?
          matches?(VIRTUAL_REGISTRIES_API_ENDPOINTS_REGEX)
        end

        def geo_proxy_workhorse_request?
          return false unless matches?(GEO_PROXY_API_PATH_REGEX)

          ::Gitlab::Workhorse.verify_api_request!(::ActionDispatch::Http::Headers.new(self))
          true
        rescue JWT::DecodeError
          false
        end

        private

        # A virtual-registry container path also matches the CE dependency proxy
        # regex, so without this exclusion a user could pick which throttle bucket
        # their request lands in.
        override :dependency_proxy_path?
        def dependency_proxy_path?
          super && !virtual_registries_api_endpoints?
        end
      end
    end
  end
end
