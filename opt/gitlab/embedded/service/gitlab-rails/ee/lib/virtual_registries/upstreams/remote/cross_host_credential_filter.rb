# frozen_string_literal: true

module VirtualRegistries
  module Upstreams
    module Remote
      module CrossHostCredentialFilter
        CREDENTIAL_HEADERS = %w[authorization cookie cookie2].freeze

        module_function

        def filter_headers(headers, source_url:, target_url:)
          return headers if same_or_subdomain_host?(source_url, target_url)

          headers.reject { |name, _| CREDENTIAL_HEADERS.include?(name.to_s.downcase) }
        end

        def same_or_subdomain_host?(source_url, target_url)
          source_host = host_for(source_url)
          target_host = host_for(target_url)
          return false unless source_host && target_host
          return true if target_host == source_host

          target_host.end_with?(".#{source_host}")
        end

        def host_for(value)
          return unless value.is_a?(String)

          Addressable::URI.parse(value)&.normalized_host
        rescue Addressable::URI::InvalidURIError, TypeError, ArgumentError
          nil
        end
      end
    end
  end
end
