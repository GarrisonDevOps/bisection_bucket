# frozen_string_literal: true

module ArtifactRegistry
  class Redaction
    REDACTED_VALUE = '[REDACTED]'
    BEARER_CREDENTIAL_PATTERN = /(bearer\s+)\S+/i
    JWT_PATTERN = /[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/

    MAX_SNIPPET = 200

    ALLOWED_CONTEXT_KEYS = %i[
      url path method status code request_id slug uuid id digest body_class list_class correlation_id
    ].freeze

    def initialize(service_token: nil)
      @service_token_forms = token_forms(service_token.presence)
    end

    def redact(text)
      scrub_service_token(text.to_s)
        .gsub(BEARER_CREDENTIAL_PATTERN, "\\1#{REDACTED_VALUE}")
        .gsub(JWT_PATTERN, REDACTED_VALUE)
    end

    def snippet(text)
      redact(text).strip.presence&.truncate(MAX_SNIPPET)
    end

    def build_context(url:, method:, correlation_id:, **context)
      allowed_context(context.merge(url: url, method: method, correlation_id: correlation_id))
    end

    def allowed_context(context)
      context.slice(*ALLOWED_CONTEXT_KEYS).compact.freeze
    end

    def redacted_exception(exception)
      message = redact(exception.message.to_s)

      redacted = rebuild(exception, message)
      redacted.set_backtrace(exception.backtrace) if exception.backtrace

      redacted
    end

    private

    def token_forms(token)
      return [] unless token

      [token, ERB::Util.url_encode(token)].uniq
    end

    def scrub_service_token(text)
      @service_token_forms.reduce(text) { |scrubbed, form| scrubbed.gsub(form, REDACTED_VALUE) }
    end

    def rebuild(exception, message)
      return exception.class.new(message) unless exception.is_a?(Errors::Error)

      exception.class.new(message, **typed_attributes(exception))
    end

    def typed_attributes(exception)
      attributes = { status: exception.status, request_id: exception.request_id }
      attributes[:code] = exception.code if exception.respond_to?(:code)

      attributes.compact
    end
  end
end
