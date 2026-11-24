# frozen_string_literal: true

module Gitlab
  # Capability checks and connection wiring for the NATS messaging system.
  #
  # `configured?` reports whether the instance has NATS connection
  # settings present, while `enabled?` additionally requires the
  # operator-controlled application setting.
  #
  # This module is the only place that reads GitLab configuration for
  # NATS; Gitlab::Nats::Client itself is configuration-source-agnostic.
  module Nats
    CLIENT_MUTEX = Mutex.new

    SIDEKIQ_INBOX_PREFIX = '_INBOX_SK'

    def self.configured?
      servers.present?
    end

    def self.enabled?
      return false unless configured?

      settings = ::Gitlab::CurrentSettings.current_application_settings

      settings.respond_to?(:use_nats_for_audit_streaming) &&
        settings.use_nats_for_audit_streaming?
    end

    def self.client
      CLIENT_MUTEX.synchronize do
        @client ||= ::Gitlab::Nats::Client.new(**connection_options)
      end
    end

    def self.connection_options
      config = settings_config || {}

      {
        servers: Array(config['servers']),
        tls: tls_options(config['tls']),
        connect_timeout: config['connect_timeout'] || Client::DEFAULT_CONNECT_TIMEOUT,
        inbox_prefix: (SIDEKIQ_INBOX_PREFIX if ::Gitlab::Runtime.sidekiq?)
      }.compact
    end

    # Normalizes the configured TLS block into a hash of file paths (ca_file,
    # cert, key) that Gitlab::Nats::Client turns into an SSLContext. Returns
    # nil when TLS is not configured (plaintext dev connections).
    def self.tls_options(tls_config)
      return unless tls_config.present?

      {
        ca_file: tls_config['ca_file'],
        cert: tls_config['cert'],
        key: tls_config['key']
      }.compact.presence
    end

    def self.servers
      Array(settings_config&.[]('servers'))
    end

    def self.settings_config
      Settings['nats']
    end

    def self.reset_client!
      CLIENT_MUTEX.synchronize do
        @client&.close
        @client = nil
      end
    end

    private_class_method :connection_options, :tls_options, :settings_config
  end
end
