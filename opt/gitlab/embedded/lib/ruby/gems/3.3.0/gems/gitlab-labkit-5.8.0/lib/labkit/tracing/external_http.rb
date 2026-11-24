# frozen_string_literal: true

module Labkit
  module Tracing
    # Instrument external HTTP calls made by the HTTP client libraries. This
    # tracing instrumenter listens to the events broadcasted from the
    # publishers injected into the libraries whenever there is a request.
    module ExternalHttp
      include Labkit::Tracing::TracingCommon

      autoload :RequestInstrumenter, "labkit/tracing/external_http/request_instrumenter"

      def self.instrument
        Labkit::NetHttpPublisher.labkit_prepend!
        Labkit::ExconPublisher.labkit_prepend!
        Labkit::HTTPClientPublisher.labkit_prepend!

        subscriptions = [
          ::ActiveSupport::Notifications.subscribe(::Labkit::EXTERNAL_HTTP_NOTIFICATION_TOPIC, RequestInstrumenter.new),
        ]

        create_unsubscriber subscriptions
      end
    end
  end
end
