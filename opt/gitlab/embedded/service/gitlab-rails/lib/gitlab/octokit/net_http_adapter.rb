# frozen_string_literal: true

module Gitlab
  module Octokit
    # Connects to the IPs validated by Gitlab::Octokit::UrlValidation instead of resolving
    # the hostname again. The URL keeps the hostname, so SNI and certificate checks still use it.
    class NetHttpAdapter < ::Faraday::Adapter::NetHttp
      def build_connection(env)
        super.tap do |http|
          candidates = env[:gitlab_candidate_addresses]
          http.gitlab_candidate_addresses = candidates

          # Each pinned IP gets its own connect attempt, so a dead IPv6 IP would hold up the IPv4 fallback
          # for Net::HTTP's 60s default.
          if candidates.present? && request_timeout(:open, env[:request]).nil?
            http.open_timeout = Gitlab::HTTP::DEFAULT_TIMEOUT_OPTIONS[:open_timeout]
          end
        end
      end
    end
  end
end
