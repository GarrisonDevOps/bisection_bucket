# frozen_string_literal: true

module EE
  module Search
    module ElasticsearchUrl
      def self.validate!(
        urls,
        deny_all_requests_except_allowed: ::Gitlab::CurrentSettings.deny_all_requests_except_allowed?,
        outbound_local_requests_allowlist: ::Gitlab::CurrentSettings.outbound_local_requests_whitelist # rubocop:disable Naming/InclusiveLanguage -- existing setting
      )
        urls.each do |url|
          ::Gitlab::HTTP_V2::UrlBlocker.validate!(url,
            schemes: %w[http https],
            allow_localhost: true,
            dns_rebind_protection: false,
            deny_all_requests_except_allowed: deny_all_requests_except_allowed,
            outbound_local_requests_allowlist: outbound_local_requests_allowlist
          )
        end
      end

      def self.with_credentials(url_string, username: nil, password: nil)
        parse(url_string).map do |uri|
          ::Search::Elastic::Helper.connection_settings(uri: uri, user: username, password: password)
        end
      end

      def self.parse(url_string)
        split_and_clean(url_string).map { |s| URI.parse(s) }
      end

      private_class_method def self.split_and_clean(url_string)
        url_string.to_s.split(',').map { |url| url.strip.gsub(%r{/*\z}, '') }.reject(&:blank?)
      end
    end
  end
end
