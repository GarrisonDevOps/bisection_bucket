# frozen_string_literal: true

# rubocop:disable Gitlab/BoundedContexts -- OmniAuth is external middleware, not a GitLab bounded context
module OmniAuth
  module Strategies
    # When a login request is proxied from a Geo secondary site (separate
    # URLs + secondary proxying), derive the OIDC redirect_uri from the
    # originating site so the OIDC callback returns to, and the session is
    # established on, the domain the user actually visited.
    #
    # Without this, the static client_options.redirect_uri is sent for every
    # login regardless of the originating site, so login can only ever
    # complete on one site's domain. See
    # https://gitlab.com/gitlab-org/gitlab/-/issues/396745.
    #
    # The identity of the proxying site comes from a JWT-signed Workhorse
    # header (Gitlab::Geo.proxied_site); requests without a valid signed
    # header, including all non-Geo instances and direct requests to the
    # primary, are unaffected and use the configured value.
    #
    # Both OIDC legs (authorization request and token exchange) call
    # #redirect_uri with the same proxied request env, so both derive the
    # same value, satisfying the OIDC redirect_uri consistency requirement.
    module GeoAwareRedirectUri
      def redirect_uri
        proxied_uri = geo_proxied_redirect_uri
        return super unless proxied_uri

        # Preserve the gem's contract of round-tripping an application-level
        # redirect_uri param (see OmniAuth::Strategies::OpenIDConnect#redirect_uri).
        return proxied_uri unless params['redirect_uri']

        "#{proxied_uri}?redirect_uri=#{CGI.escape(params['redirect_uri'])}"
      end

      private

      def geo_proxied_redirect_uri
        return unless ::Gitlab::Geo.enabled?
        return unless ::Feature.enabled?(:geo_oidc_proxied_redirect_uri, :instance, type: :ops)
        return unless ::Gitlab::Geo.proxied_site(env)

        full_host + callback_path
      end
    end
  end
end
# rubocop:enable Gitlab/BoundedContexts
