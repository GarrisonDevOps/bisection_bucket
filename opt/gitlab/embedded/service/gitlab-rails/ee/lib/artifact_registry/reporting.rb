# frozen_string_literal: true

module ArtifactRegistry
  class Reporting
    include Errors

    def initialize(base_url:, service_credential:)
      @base_url = base_url
      @service_credential = service_credential
    end

    def log_error(error, **context)
      reporter.log(error, {
        url: @base_url,
        correlation_id: resolve_correlation_id,
        status: error.try(:status),
        request_id: error.try(:request_id),
        **context
      }.compact)
    end

    def raise_terminal(error_class, message, http_method, cause: nil, **context)
      error = reporter.report_terminal(
        error_class: error_class, message: message, url: @base_url, method: http_method,
        correlation_id: resolve_correlation_id, **context
      )
      raise error, error.message, cause: cause
    end

    def report_attempt(exception, url:, method:, status:)
      reporter.report_attempt(exception, url: url, method: method, correlation_id: resolve_correlation_id,
        status: status)
    end

    def redacted_snippet(text)
      reporter.snippet(text)
    end

    private

    def reporter
      ErrorReporter.new(service_token: @service_credential.token)
    rescue AuthorizationError
      ErrorReporter.new
    end

    def resolve_correlation_id
      Labkit::Correlation::CorrelationId.current_id
    end
  end
end
