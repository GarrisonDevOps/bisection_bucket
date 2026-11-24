# frozen_string_literal: true

module ArtifactRegistry
  class ErrorReporter
    def initialize(service_token: nil, reporting_sink: Gitlab::ErrorTracking)
      @redaction = Redaction.new(service_token: service_token)
      @reporting_sink = reporting_sink
    end

    def report_terminal(error_class:, message:, url:, method:, correlation_id:, **context)
      allowed = @redaction.build_context(url: url, method: method, correlation_id: correlation_id, **context)
      error = build_exception(error_class, @redaction.redact(message), context)

      # A copy, because ErrorTracking#process_exception calls set_backtrace on an
      # exception that has none: logging the instance the client is about to raise
      # would overwrite the caller's backtrace with this frame.
      @reporting_sink.log_exception(error.dup, allowed)

      error
    end

    def report_attempt(exception, url:, method:, correlation_id:, **context)
      allowed = @redaction.build_context(url: url, method: method, correlation_id: correlation_id, **context)

      @reporting_sink.log_exception(@redaction.redacted_exception(exception), allowed)
    end

    def log(exception, context)
      @reporting_sink.log_exception(@redaction.redacted_exception(exception), @redaction.allowed_context(context))
    end

    def redact(text)
      @redaction.redact(text)
    end

    def snippet(text)
      @redaction.snippet(text)
    end

    private

    def build_exception(error_class, message, context)
      error_class.new(message, **context.slice(:status, :request_id))
    end
  end
end
