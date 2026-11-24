# frozen_string_literal: true

require 'json'
require 'faraday'
require 'cgi'
require_relative 'base_client'

module AzIdentity
  module Identity
    IDENTITY_ENDPOINT = 'http://169.254.169.254/metadata/identity/oauth2/token'
    API_VERSION = '2018-02-01'

    class ManagedIdentityClient < BaseClient
      attr_reader :resource

      def initialize(options = {})
        super()
        @environment = options[:environment]
        @resource = options[:resource] || storage_resource(@environment)
      end

      def fetch_credentials
        url = "#{identity_endpoint}?api-version=#{api_version}&resource=#{CGI.escape(resource)}"

        client_id = ENV.fetch('AZURE_CLIENT_ID', nil)
        url += "&client_id=#{client_id}" if client_id

        headers = { 'Metadata' => 'true' }
        headers['X-IDENTITY-HEADER'] = ENV['IDENTITY_HEADER'] if ENV['IDENTITY_HEADER']

        response = get(url, headers: headers)
        process_token_response(response)
      end

      private

      def identity_endpoint
        ENV['IDENTITY_ENDPOINT'] || IDENTITY_ENDPOINT
      end

      def api_version
        ENV['IDENTITY_ENDPOINT'] ? '2019-08-01' : API_VERSION
      end
    end
  end
end
