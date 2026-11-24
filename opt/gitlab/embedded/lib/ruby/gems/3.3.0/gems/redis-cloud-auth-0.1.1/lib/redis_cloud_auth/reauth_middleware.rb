# frozen_string_literal: true

module RedisCloudAuth
  # redis-client middleware that proactively re-issues AUTH on a live connection
  # shortly before a rotating access token expires, so pooled connections are
  # refreshed before the server rejects a command. Connect-time authentication
  # is handled by the callable password ({TokenCredential}); this only covers
  # already-established, long-lived connections.
  #
  # The provider caches a single token process-wide and advances its
  # `expires_at` whenever any connection triggers a refresh. Each pooled
  # connection, however, stays authenticated with whatever token it last sent
  # AUTH with. We therefore track expiry per connection (redis-client builds one
  # middleware instance per connection) rather than reading the shared provider
  # expiry, so a connection still holding the old token re-auths instead of
  # being skipped because another connection already refreshed.
  #
  # Register globally via RedisClient.register (see
  # RedisCloudAuth.register!). It is a no-op unless a credentials
  # provider descriptor is present in the connection's `custom` config under
  # :credentials_provider.
  module ReauthMiddleware
    # Re-authenticate at least this many seconds before the token expires.
    # Microsoft recommends sending the new token at least 3 minutes early.
    REAUTHENTICATION_LEEWAY = 180.0
    # Extra random lead time (0..this) added per connection so pooled
    # connections do not all re-authenticate at the same instant.
    REAUTHENTICATION_JITTER = 30.0

    def call(command, config)
      # Skip when we are issuing our own AUTH below, to avoid recursing.
      reauthenticate(config) unless auth_command?(command)
      super
    end

    def call_pipelined(commands, config)
      # The connection prelude authenticates itself via the password; when an
      # AUTH is already part of the pipeline, skip re-auth and instead record
      # the expiry of the token this connection just authenticated with.
      if commands.any? { |command| auth_command?(command) }
        result = super
        track_token_expiry(config)
        result
      else
        reauthenticate(config)
        super
      end
    end

    private

    def auth_command?(command)
      name = command.first.to_s
      return true if name.casecmp?("AUTH")

      # RESP3 connections (for example Sidekiq 7) authenticate in the prelude as
      # `HELLO 3 AUTH <user> <token>`, so treat that as an AUTH too.
      name.casecmp?("HELLO") && command.any? { |arg| arg.to_s.casecmp?("AUTH") }
    end

    # Per-connection lead time, fixed once so this connection re-authenticates
    # at a stable, slightly randomized point before expiry.
    def reauthentication_leeway
      @reauthentication_leeway ||= REAUTHENTICATION_LEEWAY + (rand * REAUTHENTICATION_JITTER)
    end

    def reauthenticate(config)
      descriptor = config.custom && config.custom[:credentials_provider]
      return unless descriptor

      provider = Registry.fetch(descriptor)

      # Decide from the expiry of the token THIS connection last authed with,
      # falling back to the provider's current expiry before the first AUTH is
      # observed. A provider that exposes no expiry can't tell us when to
      # refresh, so leave that to the reconnect path.
      expires_at = @token_expires_at || provider.expires_at
      return unless expires_at
      return if (expires_at - reauthentication_leeway) > Time.now

      token = provider.call.last
      return unless token

      client.call("AUTH", config.username, token)
      @token_expires_at = provider.expires_at
    rescue StandardError => e
      # A transient token-refresh (or AUTH) failure inside the leeway window
      # must not fail the command: the current token is still valid until
      # expiry, so log and let the operation proceed on the existing creds.
      log_reauthentication_failure(e)
    end

    # Log at most once per leeway window per connection. A sustained token
    # endpoint outage would otherwise re-enter this path and log on every Redis
    # command until the token actually expires.
    def log_reauthentication_failure(error)
      now = ::Process.clock_gettime(::Process::CLOCK_MONOTONIC)
      return if @last_failure_log_at && (now - @last_failure_log_at) < REAUTHENTICATION_LEEWAY

      @last_failure_log_at = now
      RedisCloudAuth.logger&.warn("Redis token re-authentication failed: #{error.message}")
    end

    # Remember the expiry of the token this connection authenticated with during
    # the prelude, so subsequent re-auth decisions track this connection rather
    # than the process-shared provider expiry.
    def track_token_expiry(config)
      descriptor = config.custom && config.custom[:credentials_provider]
      return unless descriptor

      @token_expires_at = Registry.fetch(descriptor).expires_at
    end
  end
end
