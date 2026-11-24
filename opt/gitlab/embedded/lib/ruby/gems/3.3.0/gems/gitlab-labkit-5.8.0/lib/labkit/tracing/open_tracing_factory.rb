# frozen_string_literal: true

module Labkit
  module Tracing
    class OpenTracingFactory
      OPENTRACING_SCHEME = "opentracing"

      def self.create_tracer(service_name, connection_string)
        return unless connection_string.present?

        opentracing_details = parse_connection_string(connection_string)
        driver_name = opentracing_details[:driver_name]

        case driver_name
        when "jaeger"
          JaegerFactory.create_tracer(service_name, opentracing_details[:options])
        else
          raise "Unknown driver: #{driver_name}"
        end
      end

      def self.parse_connection_string(connection_string)
        parsed = URI.parse(connection_string)

        raise "Invalid tracing connection string" unless valid_uri?(parsed)

        { driver_name: parsed.host, options: TracingUtils.parse_query_string(parsed.query) }
      end
      private_class_method :parse_connection_string

      def self.valid_uri?(uri)
        return false unless uri

        uri.scheme == OPENTRACING_SCHEME && uri.host.to_s =~ /^[a-z0-9_]+$/ && uri.path.empty?
      end
      private_class_method :valid_uri?
    end
  end
end
