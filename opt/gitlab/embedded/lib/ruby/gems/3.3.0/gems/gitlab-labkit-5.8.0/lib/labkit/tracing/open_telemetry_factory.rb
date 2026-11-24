# frozen_string_literal: true

require "base64"
require "cgi/escape"
require "active_support"
require "active_support/core_ext"

require "opentelemetry/sdk"
require "opentelemetry/exporter/otlp"

module Labkit
  module Tracing
    # OpenTelemetryFactory will configure OpenTelemetry distributed tracing
    class OpenTelemetryFactory
      OTLP_SCHEME = "otlp"

      # The default endpoint for OTLP HTTP exporter
      DEFAULT_HTTP_ENDPOINT = "http://localhost:4318/v1/traces"

      class << self
        # @param service_name [String] The service name for the tracer
        # @param connection_string [String] The connection string (e.g., "otlp://localhost:4318")
        # @yield [config] Optional configuration block for OpenTelemetry SDK customization
        # @yieldparam config [OpenTelemetry::SDK::Configurator] The SDK configurator
        # @return [Tracer, nil] The configured tracer or nil if initialization fails
        def create_tracer(service_name, connection_string, &)
          return unless connection_string.present?

          options = parse_otlp_connection_string(connection_string)
          # The service_name parameter from GITLAB_TRACING takes precedence over the application one
          service_name = options[:service_name] if options[:service_name]

          # parse exporter headers as necessary
          headers = build_headers(options)

          # Get sampler and exporter from GITLAB_TRACING
          sampler = get_sampler(options[:sampler], options[:sampler_param])
          exporter = get_exporter(options[:http_endpoint], options[:udp_endpoint], headers)

          # Build base resource
          base_resource = OpenTelemetry::SDK::Resources::Resource.create(
            OpenTelemetry::SemanticConventions::Resource::SERVICE_NAME => service_name
          )

          configure(service_name, base_resource, sampler, exporter, &)

          extra_params = options.except(
            :sampler,
            :sampler_param,
            :http_endpoint,
            :udp_endpoint,
            :strict_parsing,
            :debug,
            :service_name
          )

          if extra_params.present?
            message = "opentelemetry tracer: invalid option: #{extra_params.keys.join(', ')}"

            raise message if options[:strict_parsing]

            warn message
          end

          OpenTelemetry.tracer_provider.tracer(service_name)
        end

        private

        def configure(service_name, base_resource, sampler, exporter)
          if block_given?
            OpenTelemetry::SDK.configure do |c|
              c.service_name = service_name
              c.resource = base_resource

              processor = create_span_processor(exporter)
              c.add_span_processor(processor) if processor

              yield(c)
            end

            current_provider = OpenTelemetry.tracer_provider
            return unless current_provider.is_a?(OpenTelemetry::SDK::Trace::TracerProvider)

            current_provider.sampler = sampler
          else
            create_and_configure_provider(base_resource, sampler, exporter)
          end
        end

        def create_span_processor(exporter)
          return nil unless exporter

          if exporter.is_a?(OpenTelemetry::SDK::Trace::Export::ConsoleSpanExporter)
            OpenTelemetry::SDK::Trace::Export::SimpleSpanProcessor.new(exporter)
          else
            OpenTelemetry::SDK::Trace::Export::BatchSpanProcessor.new(exporter)
          end
        end

        def create_and_configure_provider(resource, sampler, exporter)
          tracer_provider = OpenTelemetry::SDK::Trace::TracerProvider.new(
            resource: resource,
            sampler: sampler
          )

          processor = create_span_processor(exporter)
          tracer_provider.add_span_processor(processor) if processor

          OpenTelemetry.tracer_provider = tracer_provider
        end

        def build_headers(options)
          return {} unless options&.key?(:http_endpoint)

          endpoint = options[:http_endpoint]
          return {} unless endpoint

          parsed = URI.parse(endpoint)

          headers = {}
          user = parsed.user
          password = parsed.password
          if user.present? && password.present?
            credentials = Base64.strict_encode64("#{CGI.unescape(user)}:#{CGI.unescape(password)}")
            headers["Authorization"] = "Basic #{credentials}"
          end

          headers
        end

        def get_sampler(sampler_type, sampler_param)
          case sampler_type
          when "probabilistic"
            sampler_rate = sampler_param ? sampler_param.to_f : Factory::DEFAULT_PROBABILISTIC_RATE
            OpenTelemetry::SDK::Trace::Samplers::TraceIdRatioBased.new(sampler_rate)
          when "const"
            if sampler_param == "1"
              OpenTelemetry::SDK::Trace::Samplers::ALWAYS_ON
            else
              OpenTelemetry::SDK::Trace::Samplers::ALWAYS_OFF
            end
          else
            OpenTelemetry::SDK::Trace::Samplers::TraceIdRatioBased.new(Factory::DEFAULT_PROBABILISTIC_RATE)
          end
        end

        def get_exporter(http_endpoint, udp_endpoint, headers)
          # OpenTelemetry doesn't support UDP, warn if specified
          # https://github.com/open-telemetry/opentelemetry-collector/discussions/6016
          warn "opentelemetry tracer: UDP endpoint not supported, ignoring udp_endpoint option" if udp_endpoint.present?

          # Check for console exporter (for development/testing)
          return get_console_exporter if http_endpoint&.include?("://console")

          get_http_exporter(http_endpoint, headers) if http_endpoint.present?
        end

        def get_http_exporter(endpoint, headers)
          OpenTelemetry::Exporter::OTLP::Exporter.new(
            endpoint: endpoint,
            headers: headers
          )
        end

        def get_console_exporter
          OpenTelemetry::SDK::Trace::Export::ConsoleSpanExporter.new
        end

        def parse_otlp_connection_string(connection_string)
          parsed = URI.parse(connection_string)

          # Parse query parameters for additional options
          options = TracingUtils.parse_query_string(parsed.query)

          # Handle console exporter (special case - no endpoint needed)
          if parsed.host == "console"
            options[:http_endpoint] = "http://console"
            return options
          end

          endpoint = build_otlp_endpoint(parsed)
          options[:http_endpoint] = endpoint

          options
        end

        def build_otlp_endpoint(uri)
          # Reconstruct the endpoint URL with scheme, host, port, and path
          scheme = uri.scheme == OTLP_SCHEME ? "http" : uri.scheme
          host = uri.host
          port = uri.port
          path = uri.path.empty? ? "" : uri.path

          # Include userinfo (username:password) if present
          userinfo = uri.userinfo ? "#{uri.userinfo}@" : ""

          # Build the endpoint
          endpoint = "#{scheme}://#{userinfo}#{host}"
          endpoint += ":#{port}" if port
          endpoint += path

          endpoint
        end
      end
    end
  end
end
