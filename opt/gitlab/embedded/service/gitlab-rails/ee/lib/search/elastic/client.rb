# frozen_string_literal: true

require 'faraday_middleware/aws_sigv4'

module Search
  module Elastic
    module Client
      AWS_ROLE_SESSION_NAME = 'gitlab_advanced_search'
      DEFAULT_ADAPTER = :typhoeus
      OPEN_TIMEOUT = 5
      NO_RETRY = 0

      # Takes a hash as returned by `ApplicationSetting#elasticsearch_config`,
      # and configures itself based on those parameters
      def self.build(config)
        return unless config

        base_config = {
          adapter: config[:client_adapter]&.to_sym || DEFAULT_ADAPTER,
          urls: config[:url],
          transport_options: {
            request: {
              timeout: config[:client_request_timeout],
              open_timeout: OPEN_TIMEOUT
            }
          },
          randomize_hosts: true,
          retry_on_failure: config[:retry_on_failure] || NO_RETRY,
          log: debug?,
          debug: debug?
        }.compact

        if config[:aws]
          creds = resolve_aws_credentials(config)
          region = config[:aws_region]

          ::Elasticsearch::Client.new(base_config) do |fmid|
            fmid.request(:aws_sigv4, credentials_provider: creds, service: 'es', region: region)
          end
        else
          ::Elasticsearch::Client.new(base_config)
        end
      end

      def self.debug?
        Gitlab.dev_or_test_env? && Gitlab::Utils.to_boolean(ENV['ELASTIC_CLIENT_DEBUG'])
      end

      def self.resolve_aws_credentials(config)
        Gitlab::Aws::CredentialsResolver.resolve(
          region: config[:aws_region],
          role_arn: config[:aws_role_arn],
          role_session_name: AWS_ROLE_SESSION_NAME,
          access_key_id: config[:aws_access_key],
          secret_access_key: config[:aws_secret_access_key]
        )
      end
    end
  end
end
