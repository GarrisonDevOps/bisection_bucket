# frozen_string_literal: true

module Gitlab
  module Octokit
    class UrlValidation
      def initialize(app)
        @app = app
      end

      def call(env)
        result = Gitlab::HTTP_V2::UrlBlocker.validate_url_with_proxy!(env[:url],
          schemes: %w[http https],
          allow_localhost: allow_local_requests?,
          allow_local_network: allow_local_requests?,
          dns_rebind_protection: dns_rebind_protection?,
          deny_all_requests_except_allowed: Gitlab::CurrentSettings.deny_all_requests_except_allowed?,
          outbound_local_requests_allowlist: Gitlab::CurrentSettings.outbound_local_requests_whitelist # rubocop:disable Naming/InclusiveLanguage -- existing setting
        )

        # FollowRedirects reuses this env on every hop, so always overwrite the previous hop's value.
        env[:gitlab_candidate_addresses] = candidate_addresses(result)

        @app.call(env)
      end

      private

      def candidate_addresses(result)
        # IP-allowlisted hosts return before ip_addresses is set, but the URI is already rewritten to the pinned IP.
        return [result.uri.hostname] if result.ip_addresses.nil? && result.hostname

        # Cap to one candidate per family so N black-holed IPs cannot force N * open_timeout.
        result.ip_addresses&.group_by { |ip| ip.include?(':') }&.values&.map(&:first)
      end

      def dns_rebind_protection?
        return false if Gitlab.http_proxy_env?

        Gitlab::CurrentSettings.dns_rebinding_protection_enabled?
      end

      def allow_local_requests?
        Gitlab::CurrentSettings.allow_local_requests_from_web_hooks_and_services?
      end
    end
  end
end
