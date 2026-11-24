# frozen_string_literal: true

require 'uri'

module Gitlab
  module Redis
    class ConfigGenerator
      CommandExecutionError = Class.new(StandardError)
      InvalidPathError = Class.new(StandardError)
      CredentialsProviderError = Class.new(StandardError)

      attr_reader :component

      def self.parse_client_tls_options(config)
        return config unless config&.key?(:ssl_params)

        # Only cert_file and key_file are handled in this method. ca_file and
        # ca_path are Strings, so they can be passed as-is. cert_store is not
        # currently supported. Note that this is no longer needed now that
        # redis-client does this conversion for us with the cert and key parameters,
        # but preserve this for backwards compatibility.
        cert_file = config[:ssl_params].delete(:cert_file)
        key_file = config[:ssl_params].delete(:key_file)

        if cert_file
          unless ::File.exist?(cert_file)
            raise InvalidPathError,
              "Certificate file #{cert_file} specified in Redis configuration does not exist."
          end

          config[:ssl_params][:cert] = OpenSSL::X509::Certificate.new(File.read(cert_file))
        end

        if key_file
          unless ::File.exist?(key_file)
            raise InvalidPathError,
              "Key file #{key_file} specified in Redis configuration does not exist."
          end

          config[:ssl_params][:key] = OpenSSL::PKey.read(File.read(key_file))
        end

        config
      end

      # Transforms a `credentials_provider` config entry into a callable
      # password that returns a fresh access token on every (re)connect, plus a
      # marshallable descriptor (stashed under :credentials_provider_descriptor)
      # that Wrapper#params moves into `custom` for the re-auth middleware.
      #
      # `credentials_provider` may be a String (the provider name, e.g.
      # "azure") or a Hash of provider options. The AUTH username is taken from
      # the connection's `username` (the managed identity / service principal
      # object ID).
      def self.parse_credentials_provider(config)
        return config unless config

        provider_config = config.delete(:credentials_provider)
        return config unless provider_config

        # Entra-style token auth targets managed Redis (Azure Cache for Redis /
        # Azure Managed Redis), which is reached through a single endpoint. A
        # client-visible multi-node topology (Sentinel or Cluster) means
        # self-managed Redis, which does not validate these tokens, so the
        # combination is not supported.
        if config[:sentinels].present? || config[:cluster].present?
          raise CredentialsProviderError,
            'credentials_provider is not supported with Redis Sentinel or Cluster. Set the Redis ' \
              'URL to the managed Redis endpoint instead of configuring sentinels or cluster.'
        end

        # The token is a bearer credential, so refuse to send it over a plaintext
        # connection.
        unless tls_enabled?(config)
          raise CredentialsProviderError,
            'credentials_provider requires a TLS connection. Use a rediss:// URL or enable ssl.'
        end

        descriptor = credentials_descriptor(provider_config, config[:username])
        config[:password] = build_token_credential(descriptor)
        config[:credentials_provider_descriptor] = descriptor
        config
      end

      # mail_room loads this file with require_relative and no Zeitwerk, so the
      # redis-cloud-auth gem is not loaded there and `RedisCloudAuth` is
      # undefined. Turn the resulting NameError into a clear "not supported yet"
      # message instead of a confusing uninitialized-constant error.
      def self.build_token_credential(descriptor)
        RedisCloudAuth.credential(descriptor)
      rescue NameError
        raise CredentialsProviderError,
          'credentials_provider is not supported in this context (for example mail_room) yet.'
      end

      # Mirror how Wrapper#parse_redis_url resolves TLS: it derives `ssl` from a
      # `rediss://` scheme but then lets an explicit `ssl` in the config win, so
      # an explicit `ssl: false` still connects over plaintext. Match that here
      # so the guard agrees with the connection that is actually made.
      def self.tls_enabled?(config)
        return !!config[:ssl] if config.key?(:ssl)

        URI.parse(config[:url].to_s).scheme == 'rediss'
      rescue URI::InvalidURIError
        false
      end

      def self.credentials_descriptor(provider_config, username)
        descriptor =
          if provider_config.is_a?(Hash)
            provider_config.symbolize_keys
          else
            { provider: provider_config }
          end

        descriptor[:username] ||= username
        descriptor.freeze
      end

      def initialize(component = 'Redis')
        @component = component
      end

      def generate(original_config)
        command = original_config.delete(:config_command)
        config = if command.present?
                   config_from_command = generate_yaml_from_command(command)
                   config_from_command.present? ? original_config.deep_merge(config_from_command) : original_config
                 else
                   original_config
                 end

        config = self.class.parse_client_tls_options(config)
        self.class.parse_credentials_provider(config)
      end

      private

      def generate_yaml_from_command(command)
        cmd = command.split(" ")
        output, exit_status = Gitlab::Popen.popen(cmd)

        if exit_status != 0
          raise CommandExecutionError,
            "#{component}: Execution of `#{command}` failed with exit code #{exit_status}." \
              "Output: #{output}"
        end

        parsed_output = YAML.safe_load(output)

        unless parsed_output.is_a?(Hash)
          raise CommandExecutionError,
            "#{component}: The output of `#{command}` must be a Hash, #{parsed_output.class} given." \
              "Output: #{parsed_output}"
        end

        parsed_output.deep_symbolize_keys
      rescue Psych::SyntaxError => e
        error_message = <<~MSG
          #{component}: Execution of `#{command}` generated invalid yaml.
          Error: #{e.problem} #{e.context} at line #{e.line} column #{e.column}
        MSG
        raise CommandExecutionError, error_message
      end
    end
  end
end
