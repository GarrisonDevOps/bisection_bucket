# frozen_string_literal: true

module Labkit
  ##
  # Prepend to HTTPClient class to publish an ActiveSupport::Notifcation
  # whenever a HTTP request is triggered.
  #
  # Similar to Net::HTTP, this HTTP client redirects all calls to
  # HTTPClient#do_get_block. HTTPClient is prepended with HTTPClientPublisher.
  # Although HTTPClient supports request filter (a kind of middleware), its
  # support is strictly limited. The request and response passed into the
  # filter don't contain connection information. The response doesn't even
  # contain any link to the request object. It's impossible to fit this filter
  # mechanism into our subscribing model.
  #
  # For more information;
  # https://github.com/nahi/httpclient/blob/d3091b095a1b29f65f4531a70a8e581e75be035e/lib/httpclient.rb#L1233
  module HTTPClientPublisher
    @prepend_mutex = Mutex.new

    def self.labkit_prepend!
      @prepend_mutex.synchronize do
        return if !defined?(HTTPClient) || @prepended

        HTTPClient.prepend(self)
        @prepended = true
      end
    end

    def do_get_block(req, proxy, conn, &block)
      start_time = ::Labkit::System.monotonic_time
      ActiveSupport::Notifications.instrument ::Labkit::EXTERNAL_HTTP_NOTIFICATION_TOPIC, create_request_payload(req, proxy) do |payload|
        response =
          begin
            super
          ensure
            payload[:duration] = (::Labkit::System.monotonic_time - start_time).to_f
          end
        payload[:code] = response.status_code.to_s
        response
      end
    end

    private

    def create_request_payload(request, proxy)
      http_header = request.http_header
      payload = {
        method: http_header.request_method,
        host: http_header.request_uri.host,
        path: http_header.request_uri.path,
        port: http_header.request_uri.port,
        scheme: http_header.request_uri.scheme,
        query: http_header.request_uri.query,
        fragment: http_header.request_uri.fragment,
      }

      unless proxy.nil?
        payload[:proxy_host] = proxy.host
        payload[:proxy_port] = proxy.port
      end

      payload
    end
  end
end
