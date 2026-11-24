# frozen_string_literal: true

module ArtifactRegistry
  module Configuration
    ALLOWED_SCHEMES = %w[http https].freeze
    private_constant :ALLOWED_SCHEMES

    class << self
      def api_url
        Gitlab.config.artifact_registry['api_url']
      end

      def configured?
        parsed = ::Gitlab::Utils.parse_url(api_url)

        return false unless parsed

        base_url_violation(parsed).nil?
      end

      def base_url_violation(uri)
        return 'base_url must be an http(s) URL' unless ALLOWED_SCHEMES.include?(uri.scheme)
        return 'base_url must have a host' if uri.hostname.blank?

        if uri.userinfo.present? || uri.query.present? || uri.fragment.present?
          return 'base_url must not carry user, query, or fragment'
        end

        'base_url must not carry a path' if uri.path.present? && uri.path != '/'
      end

      def client_base_url
        return unless configured?

        ::Gitlab::UrlHelpers.normalized_base_url(api_url)
      end

      # Read by hash key, like api_url: the method reader raises
      # Gitlab::Configs::MissingConfig on an unset key, and the credential path
      # must resolve to nil and fail closed instead.
      def service_token_secret_file
        Gitlab.config.artifact_registry['service_token']&.[]('secret_file')
      end
    end
  end
end
