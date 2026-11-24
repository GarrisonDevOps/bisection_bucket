# frozen_string_literal: true

module Banzai
  module IframeProviders
    PROVIDERS_PATH = Rails.root.join('config/iframe_providers.yml').freeze

    PERMITTED_SANDBOX_FLAGS = %w[
      allow-scripts
      allow-same-origin
      allow-popups
      allow-popups-to-escape-sandbox
      allow-presentation
    ].freeze

    PLACEHOLDER = /\{(\w+)\}/

    ConfigError = Class.new(StandardError)

    Match = Struct.new(:url, :view, :provider, keyword_init: true)

    class << self
      def match(url)
        return if url.blank?

        uri = begin
          Addressable::URI.parse(url)
        rescue Addressable::URI::InvalidURIError
          nil
        end

        return unless uri&.normalized_scheme == 'https' && uri.to_s == url && plain_authority?(uri)

        enabled_providers.each do |provider|
          match = provider.match(uri)
          return match if match
        end

        nil
      end

      def known_providers
        @known_providers ||= load_providers
      end

      def enabled_providers
        allowlist = Gitlab::CurrentSettings.iframe_rendering_allowlist
        known_providers.select { |provider| allowlist.include?(provider.id) }
      end

      def frontend_config
        enabled_providers.to_h do |provider|
          [provider.id, {
            name: provider.name,
            match_hosts: provider.matches.map(&:host).uniq,
            src_origin: provider.src_origin,
            src_template: provider.src,
            view_template: provider.view,
            sandbox: provider.sandbox.join(' '),
            require_activation: provider.require_activation
          }]
        end
      end

      def reset!
        @known_providers = nil
      end

      private

      def plain_authority?(uri)
        uri.host.present? && !trailing_dot?(uri.host) && uri.userinfo.nil? && uri.normalized_port.nil?
      end

      def trailing_dot?(host)
        Addressable::IDNA.to_ascii(Addressable::URI.unencode_component(host)).end_with?('.')
      end

      def load_config!
        YAML.safe_load_file(PROVIDERS_PATH)
      rescue Psych::Exception => e
        raise ConfigError, "#{PROVIDERS_PATH.basename}: #{e.message}"
      end

      def load_providers
        load_providers!
      rescue ConfigError => e
        Gitlab::AppLogger.error(
          message: 'Ignoring iframe provider configuration',
          Labkit::Fields::ERROR_MESSAGE => e.message
        )

        [].freeze
      end

      def load_providers!
        config = load_config!
        raise ConfigError, "#{PROVIDERS_PATH.basename}: expected a mapping of provider IDs" unless config.is_a?(Hash)

        config.map { |id, entry| Provider.from_config(id, entry) }.freeze
      end
    end
  end
end
