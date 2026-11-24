# frozen_string_literal: true

module Labkit
  ##
  # A middleware for Excon HTTP library to publish a notification
  # whenever a HTTP request is triggered.
  #
  # Excon supports a middleware system that allows request/response
  # interception freely. Whenever a new Excon connection is created, a list of
  # default middlewares is injected. This list of middlewares can be altered
  # thanks to Excon.defaults accessor. ExconPublisher is inserted into this
  # list. It affects all connections created in future. There is a limitation
  # that this approach doesn't work if a user decides to override the default
  # middleware list. It is unlikely though, at least in the dependency tree of
  # GitLab.
  #
  # ExconPublisher instance is created once and shared between all Excon
  # connections later. Each connection may be triggered by different threads in
  # parallel. In such cases, a connection objects creates multiple sockets for
  # each thread. Therfore in the implementation of this middleware, the
  # instrumation payload for each connection is stored inside a thread-isolated
  # storage.
  #
  # For more information:
  # https://github.com/excon/excon/blob/81a0130537f2f8cd00d6daafb05d02d9a90dc9f7/lib/excon/middlewares/base.rb
  # https://github.com/excon/excon/blob/fa3ec51e9bb062a12846a1cfff09534e76c99f4b/lib/excon/constants.rb#L146
  # https://github.com/excon/excon/blob/fa3ec51e9bb062a12846a1cfff09534e76c99f4b/lib/excon/connection.rb#L474
  class ExconPublisher
    @prepend_mutex = Mutex.new

    def self.labkit_prepend!
      @prepend_mutex.synchronize do
        return if !defined?(Excon) || @prepended

        defaults = Excon.defaults
        defaults[:middlewares] << ExconPublisher

        @prepended = true
      end
    end

    def initialize(stack)
      @stack = stack
      @instrumenter = ActiveSupport::Notifications.instrumenter
    end

    def request_call(datum)
      payload = start_payload(datum)
      store_connection_payload(datum, payload)
      @instrumenter.start(::Labkit::EXTERNAL_HTTP_NOTIFICATION_TOPIC, payload)
      @stack.request_call(datum)
    end

    def response_call(datum)
      payload = fetch_connection_payload(datum)

      return @stack.response_call(datum) if payload.nil?

      calculate_duration(payload)
      payload[:code] = datum[:response][:status].to_s

      @instrumenter.finish(::Labkit::EXTERNAL_HTTP_NOTIFICATION_TOPIC, payload)
      @stack.response_call(datum)
    ensure
      remove_connection_payload(datum)
    end

    def error_call(datum)
      payload = fetch_connection_payload(datum)

      return @stack.error_call(datum) if payload.nil?

      calculate_duration(payload)

      if datum[:error].is_a?(Exception)
        payload[:exception] = [datum[:error].class.name, datum[:error].message]
        payload[:exception_object] = datum[:error]
      elsif datum[:error].is_a?(String)
        exception = StandardError.new(datum[:error])
        payload[:exception] = [exception.class.name, exception.message]
        payload[:exception_object] = exception
      end

      @instrumenter.finish(::Labkit::EXTERNAL_HTTP_NOTIFICATION_TOPIC, payload)
      @stack.error_call(datum)
    ensure
      remove_connection_payload(datum)
    end

    private

    def start_payload(datum)
      payload = {
        method: datum[:method].to_s.upcase,
        host: nil_or_string(datum[:host]),
        path: nil_or_string(datum[:path]),
        port: nil_or_int(datum[:port]),
        scheme: nil_or_string(datum[:scheme]),
        query: generate_query_string(datum[:query]),
        start_time: ::Labkit::System.monotonic_time,
      }

      unless datum[:proxy].nil?
        payload[:proxy_host] = datum[:proxy][:host]
        payload[:proxy_port] = datum[:proxy][:port]
      end

      payload
    end

    def calculate_duration(payload)
      start_time = payload.delete(:start_time) || ::Labkit::System.monotonic_time
      payload[:duration] = (::Labkit::System.monotonic_time - start_time).to_f
    end

    def connection_payload
      Thread.current[:__labkit_http_excon_payload] ||= {}
    end

    def store_connection_payload(datum, payload)
      connection_payload[datum[:connection]] = payload
    end

    def fetch_connection_payload(datum)
      connection_payload.fetch(datum[:connection], nil)
    end

    def remove_connection_payload(datum)
      connection_payload.delete(datum[:connection])
    end

    def nil_or_string(str)
      str&.to_s
    end

    def nil_or_int(int)
      int&.to_i
    rescue StandardError
      nil
    end

    def generate_query_string(query)
      if query.is_a?(Hash)
        query.to_query
      else
        nil_or_string(query)
      end
    end
  end
end
