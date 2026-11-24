# frozen_string_literal: true

require 'json'
require_relative 'base_client'

module Fog
  module AzureRM
    # DefaultCredentials attempts to resolve the credentials necessary to access
    # the Azure service.
    class DefaultCredentials
      def initialize(options)
        @options = options
        @credential_client = nil
      end

      def fetch_credentials_if_needed
        return unless credential_client

        credential_client.fetch_credentials_if_needed
      end

      private

      attr_reader :options

      def credential_client
        return @credential_client if @credential_client

        clients = [
          Fog::AzureRM::Identity::WorkflowIdentityClient,
          Fog::AzureRM::Identity::ManagedIdentityClient
        ]

        credentials = nil
        clients.each do |klass|
          client = klass.new(options)

          begin
            credentials = client.fetch_credentials_if_needed
          rescue Fog::AzureRM::Identity::BaseClient::FetchCredentialsError
            next
          end

          if credentials
            @credential_client = client
            break
          end
        end

        @credential_client
      end
    end
  end
end
