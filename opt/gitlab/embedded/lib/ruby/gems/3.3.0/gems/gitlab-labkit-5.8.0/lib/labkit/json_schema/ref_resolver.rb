# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'
require 'active_support/core_ext/module/attribute_accessors'

module Labkit
  module JsonSchema
    # This class resolves JSON schema references (e.g., "$ref": "http://example.com/schema.json")
    # by fetching remote schemas over HTTP/HTTPS and caching them.
    # It is used by JSONSchemer to resolve external schema definitions.
    # We need it to validate JSON data against schemas that might be hosted remotely.
    class RefResolver
      mattr_accessor :cache, default: {}

      def initialize(timeout_s: 2)
        @timeout_s = timeout_s
      end

      def call(uri)
        uri_str = uri.to_s

        return cache[uri_str] if cache.key?(uri_str)

        cache[uri_str] = fetch_remote_schema(uri_str)
      end

      private

      def fetch_remote_schema(uri_str)
        uri = URI(uri_str)

        raise(JSONSchemer::UnknownRef, "Unsupported URI scheme: #{uri_str}") unless %w[http https].include?(uri.scheme)

        response = Net::HTTP.start(
          uri.host,
          uri.port,
          use_ssl: uri.scheme == 'https',
          open_timeout: @timeout_s,
          read_timeout: @timeout_s
        ) do |http|
          request = Net::HTTP::Get.new(uri.request_uri)
          http.request(request)
        end

        unless response.is_a?(Net::HTTPSuccess)
          raise(
            JSONSchemer::UnknownRef,
            "Failed to fetch #{uri_str}: #{response.code} #{response.message}"
          )
        end

        JSON.parse(response.body)
      rescue Net::OpenTimeout, Net::ReadTimeout => e
        raise(JSONSchemer::UnknownRef, "Timeout fetching #{uri_str}: #{e.message}")
      rescue JSON::ParserError => e
        raise(JSONSchemer::UnknownRef, "Invalid JSON at #{uri_str}: #{e.message}")
      rescue SocketError, Errno::ECONNREFUSED => e
        raise(JSONSchemer::UnknownRef, "Connection failed for #{uri_str}: #{e.message}")
      end
    end
  end
end
