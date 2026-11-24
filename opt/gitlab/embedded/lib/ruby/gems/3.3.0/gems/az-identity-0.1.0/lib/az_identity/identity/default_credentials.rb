# frozen_string_literal: true

require 'json'
require_relative 'base_client'
require_relative 'workload_identity_client'
require_relative 'managed_identity_client'

module AzIdentity
  class DefaultCredentials
    CLIENTS = [
      AzIdentity::Identity::WorkloadIdentityClient,
      AzIdentity::Identity::ManagedIdentityClient
    ].freeze

    def initialize(options = {})
      @options = options
      @credential_client = nil
      @mutex = Mutex.new
    end

    def fetch_credentials_if_needed
      return unless credential_client

      credential_client.fetch_credentials_if_needed
    end

    private

    attr_reader :options

    def credential_client
      return @credential_client if @credential_client

      @mutex.synchronize do
        @credential_client ||= discover_client
      end
    end

    def discover_client
      CLIENTS.each do |klass|
        client = klass.new(options)
        return client if try_fetch_credentials(client)
      end

      nil
    end

    # A credential source that is not configured in this environment should be
    # skipped so the next one is tried, rather than aborting discovery of the
    # remaining sources.
    def try_fetch_credentials(client)
      client.fetch_credentials_if_needed
    rescue StandardError
      nil
    end
  end
end
