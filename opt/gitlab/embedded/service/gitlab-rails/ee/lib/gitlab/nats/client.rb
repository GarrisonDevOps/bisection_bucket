# frozen_string_literal: true

module Gitlab
  module Nats
    # Thin, business-logic-free wrapper around the NATS JetStream client.
    #
    # This class is deliberately isolated: it has no knowledge of audit
    # events or any other GitLab domain, and it never reads GitLab
    # `Settings`, `Feature`, or application settings. All connection
    # configuration is injected through the constructor (resolved by
    # Gitlab::Nats.client). This keeps the contract swappable for an
    # infra-provided shared client and makes future gem extraction trivial.
    class Client
      DEFAULT_CONNECT_TIMEOUT = 2 # seconds
      DEFAULT_PUBLISH_TIMEOUT = 2.0 # seconds
      MAX_RECONNECT_ATTEMPTS = 3
      RECONNECT_TIME_WAIT = 1 # seconds

      MESSAGE_ID_HEADER = 'Nats-Msg-Id'

      Error = Class.new(StandardError)
      # An unreachable broker, distinct so callers can treat it as
      # non-retryable rather than a raw Errno/NATS::IO backtrace.
      ConnectionError = Class.new(Error)

      # Broad set for the initial connect (no timeout/NotFound to confuse there).
      CONNECTION_ERRORS = [::NATS::IO::Error, SocketError, SystemCallError].freeze

      # Narrow set for an already-open connection: NATS::Timeout and
      # JetStream::Error::NotFound are also NATS::IO::Error but are normal
      # outcomes, so only true connection-death errors belong here. A timeout
      # is deliberately not a reset trigger (the caller retries at a higher
      # level); if the connection is actually dead, the next call raises a
      # ConnectionClosedError below and recovers then.
      CONNECTION_LOST_ERRORS = [
        ::NATS::IO::ConnectionClosedError,
        ::NATS::IO::StaleConnectionError,
        ::NATS::IO::ConnectionDrainingError,
        SocketError,
        SystemCallError
      ].freeze

      def initialize(servers:, tls: nil, connect_timeout: DEFAULT_CONNECT_TIMEOUT, inbox_prefix: nil)
        raise ArgumentError, 'servers must be present' if Array(servers).empty?

        @servers = Array(servers)
        @tls = tls
        @connect_timeout = connect_timeout
        @inbox_prefix = inbox_prefix
        @mutex = Mutex.new
      end

      # Synchronous JetStream publish. Blocks until the server acknowledges
      # the message or `timeout` elapses.
      #
      # @param subject [String] subject to publish to
      # @param payload [String] serialized message body
      # @param message_id [String] stable ID used for JetStream dedup
      #   (Nats-Msg-Id header) within the stream's duplicate window
      # @param timeout [Float] seconds to wait for the pub-ack
      # @return [NATS::JetStream::PubAck]
      # @raise [NATS::Timeout, NATS::JetStream::Error] on ack timeout or
      #   stream errors
      def publish(subject, payload, message_id:, timeout: DEFAULT_PUBLISH_TIMEOUT)
        with_connection do |js|
          js.publish(
            subject,
            payload,
            timeout: timeout,
            header: { MESSAGE_ID_HEADER => message_id }
          )
        end
      end

      # Binds (or creates) a durable pull consumer subscription.
      #
      # The returned subscription supports `fetch(batch_size, timeout:)`
      # returning an array of messages, each responding to `data`, `header`,
      # and `ack`.
      #
      # @param subject [String] subject filter to consume from
      # @param durable [String] durable consumer name
      # @param stream [String, nil] stream name; resolved by subject lookup
      #   when omitted
      # @return [NATS::JetStream::PullSubscription]
      def pull_subscribe(subject, durable:, stream: nil)
        params = {}
        params[:stream] = stream if stream

        with_connection { |js| js.pull_subscribe(subject, durable, params) }
      end

      # Returns the stream's info, or nil when the stream does not exist.
      #
      # @param name [String] stream name
      # @return [NATS::JetStream::API::StreamInfo, nil]
      def stream_info(name)
        with_connection { |js| js.stream_info(name) }
      rescue ::NATS::JetStream::Error::NotFound
        nil
      end

      # Creates a stream.
      #
      # @param config [Hash] JetStream stream configuration (name, subjects,
      #   retention, storage, num_replicas, max_age, duplicate_window, ...)
      # @return [NATS::JetStream::API::StreamCreateResponse]
      def add_stream(config)
        with_connection { |js| js.add_stream(**config) }
      end

      # Updates an existing stream's configuration.
      #
      # @param config [Hash] JetStream stream configuration
      # @return [NATS::JetStream::API::StreamCreateResponse]
      def update_stream(config)
        with_connection { |js| js.update_stream(**config) }
      end

      # Returns a consumer's info, or nil when the consumer does not exist.
      #
      # @param stream [String] stream name
      # @param name [String] consumer name
      # @return [NATS::JetStream::API::ConsumerInfo, nil]
      def consumer_info(stream, name)
        with_connection { |js| js.consumer_info(stream, name) }
      rescue ::NATS::JetStream::Error::NotFound
        nil
      end

      # Creates a consumer, or updates it in place when it already exists.
      #
      # @param stream [String] stream name
      # @param config [Hash] JetStream consumer configuration. `ack_wait` is
      #   in integer seconds; `backoff` is in nanoseconds.
      # @return [NATS::JetStream::API::ConsumerInfo]
      def add_consumer(stream, config)
        with_connection { |js| js.add_consumer(stream, config) }
      end

      def connected?
        connection = @mutex.synchronize { @connection }

        !!connection&.connected?
      end

      def close
        @mutex.synchronize do
          @connection&.close
          @connection = nil
          @jetstream = nil
        end
      end

      private

      # On a mid-flight connection drop, reset the memoized connection and
      # raise ConnectionError so the next call reconnects instead of reusing a
      # dead one. jetstream is resolved outside the rescue so connect-time and
      # config errors keep their own handling.
      def with_connection
        js = jetstream

        begin
          yield js
        rescue *CONNECTION_LOST_ERRORS => e
          reset!
          raise ConnectionError, "NATS connection lost: #{e.message}"
        end
      end

      def reset!
        @mutex.synchronize do
          # Best-effort close before dropping the reference so a flapping broker
          # does not leak a connection (and its reader/flusher threads) per drop.
          # The socket is likely already dead, so close may itself raise.
          @connection&.close rescue nil # rubocop:disable Style/RescueModifier -- best-effort teardown of a dead connection
          @connection = nil
          @jetstream = nil
        end
      end

      def jetstream
        @mutex.synchronize do
          @jetstream ||= connection.jetstream
        end
      end

      # Must be called while holding @mutex.
      def connection
        return @connection if @connection

        # Built outside the rescue so config errors (e.g. an unreadable cert
        # file) surface as themselves; only the connect maps to ConnectionError.
        options = connect_options

        @connection = begin
          ::NATS.connect(nil, options)
        rescue *CONNECTION_ERRORS => e
          raise ConnectionError, "NATS connection failed: #{e.message}"
        end
      end

      def connect_options
        options = {
          servers: @servers,
          connect_timeout: @connect_timeout,
          reconnect: true,
          max_reconnect_attempts: MAX_RECONNECT_ATTEMPTS,
          reconnect_time_wait: RECONNECT_TIME_WAIT
        }

        options[:custom_inbox_prefix] = @inbox_prefix if @inbox_prefix

        tls_context = build_tls_context
        # nats-pure ignores bare ca_file/cert/key; it only reads a prepared
        # SSLContext under `context:` (NATS::IO::Client#tls_context).
        options[:tls] = { context: tls_context } if tls_context

        options
      end

      def build_tls_context
        return unless @tls

        OpenSSL::SSL::SSLContext.new.tap do |context|
          context.set_params
          context.ca_file = @tls[:ca_file] if @tls[:ca_file]
          load_client_certificate(context) if @tls[:cert]
          context.key = OpenSSL::PKey.read(File.read(@tls[:key])) if @tls[:key]
          context.verify_mode = OpenSSL::SSL::VERIFY_PEER
        end
      end

      def load_client_certificate(context)
        # A cert file may bundle the leaf with intermediates; the leaf is the
        # client cert, the rest is the chain the server needs to verify it.
        leaf, *chain = ::Gitlab::X509::Certificate.load_ca_certs_bundle(File.read(@tls[:cert]))

        raise Error, "no certificate found in #{@tls[:cert]}" unless leaf

        context.cert = leaf
        context.extra_chain_cert = chain if chain.any?
      end
    end
  end
end
