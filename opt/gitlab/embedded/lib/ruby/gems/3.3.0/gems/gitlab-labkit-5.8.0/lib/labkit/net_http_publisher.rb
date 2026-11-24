# frozen_string_literal: true

module Labkit
  ##
  # Prepend to Ruby's Net/HTTP standard HTTP library to publish a notification
  # whenever a HTTP request is triggered. Net::HTTP has different class methods
  # for each http method. Those methods are delegated to corresponding instance
  # methods. Eventually, `request` method is call to dispatch the HTTP request.
  # Therefore, a prepender that override `request` method covers all HTTP
  # calls.
  #
  # For more information:
  # https://github.com/ruby/ruby/blob/9b9cbbbc17bb5840581c7da37fd0feb0a7d4c1f3/lib/net/http.rb#L1510
  #
  # Note: some use cases to take care of
  # - Create a request from input URI
  # - Create a request from input host, port, and path string
  # - Create a singular request and closes the connection immediately
  # - Create a persistent connection and perform multiple HTTP requests
  # - Notification payload must separate URI components
  # - Create a post request with a body
  # - Create a post request with form data
  # - Create a request with basic authentication
  # - Make a request via a proxy server
  # - Streaming
  module NetHttpPublisher
    @prepend_mutex = Mutex.new

    def self.labkit_prepend!
      @prepend_mutex.synchronize do
        return if @prepended

        require "net/http"
        Net::HTTP.prepend(self)
        @prepended = true
      end
    end

    def request(request, *args, &block)
      return super unless started?

      start_time = ::Labkit::System.monotonic_time

      inject_trace_context(request)

      ActiveSupport::Notifications.instrument ::Labkit::EXTERNAL_HTTP_NOTIFICATION_TOPIC, create_request_payload(request) do |payload|
        response =
          begin
            super
          ensure
            # Fold in any connection-establishment time (DNS/TCP/TLS) measured by
            # `#do_start`, so a slow connect is attributed to the request instead
            # of vanishing. Counted once, on the first request of the connection.
            payload[:duration] = (::Labkit::System.monotonic_time - start_time).to_f + take_connect_duration
          end
        payload[:code] = response.code
        response
      end
    end

    # Net::HTTP establishes the connection (DNS resolution, TCP connect, TLS
    # handshake) here, before any `#request` runs. With the explicit-start
    # pattern (`Net::HTTP.start(host) { |http| http.request(...) }`) this happens
    # entirely outside `#request`, so without instrumenting it a connection that
    # hangs -- or fails with e.g. Net::OpenTimeout before any request is sent --
    # would contribute nothing to external_http timing or counts.
    def do_start
      start_time = ::Labkit::System.monotonic_time

      begin
        super
      rescue StandardError
        # The connection failed before any request could be sent, so `#request`
        # will never run to attribute this time. Emit a standalone event so the
        # failure and the time spent are still visible.
        ActiveSupport::Notifications.instrument(
          ::Labkit::EXTERNAL_HTTP_NOTIFICATION_TOPIC, create_connect_payload
        ) do |payload|
          payload[:duration] = (::Labkit::System.monotonic_time - start_time).to_f
          raise
        end
      end

      @labkit_connect_duration = (::Labkit::System.monotonic_time - start_time).to_f
    end
    private :do_start

    private

    def take_connect_duration
      duration = @labkit_connect_duration || 0.0
      @labkit_connect_duration = nil
      duration
    end

    def create_connect_payload
      {
        method: nil,
        host: address,
        port: port,
        scheme: use_ssl? ? "https" : "http",
        path: nil,
        query: nil,
        fragment: nil
      }.tap do |payload|
        if proxy?
          payload[:proxy_host] = proxy_address
          payload[:proxy_port] = proxy_port
        end
      end
    end

    def create_request_payload(request)
      payload = {
        method: request.method
      }

      if request.uri.nil?
        path_uri = URI(request.path)
        payload[:host] = address
        payload[:path] = path_uri.path
        payload[:port] = port
        payload[:scheme] = use_ssl? ? "https" : "http"
        payload[:query] = path_uri.query
        payload[:fragment] = path_uri.fragment
      else
        payload[:host] = request.uri.host
        payload[:path] = request.uri.path
        payload[:port] = request.uri.port
        payload[:scheme] = request.uri.scheme
        payload[:query] = request.uri.query
        payload[:fragment] = request.uri.fragment
      end

      if proxy?
        payload[:proxy_host] = proxy_address
        payload[:proxy_port] = proxy_port
      end

      payload
    end

    def inject_trace_context(request)
      return unless Labkit::Tracing.enabled?

      tracer = Labkit::Tracing::TracingUtils.tracer
      span = tracer.active_span
      return if span.nil?

      carrier = {}
      tracer.inject_context(span, carrier)

      carrier.each do |key, value|
        request[key] = value
      end
    rescue StandardError
      warn "Labkit::NetHttpPublisher: trace context propagation failed"
    end
  end
end
