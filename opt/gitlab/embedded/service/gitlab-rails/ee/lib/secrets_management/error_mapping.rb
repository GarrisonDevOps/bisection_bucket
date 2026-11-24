# frozen_string_literal: true

module SecretsManagement
  module ErrorMapping
    ERROR_MAPPINGS = {
      /(metadata check-and-set parameter does not match|check-and-set parameter did not match)/ =>
        "This resource was recently modified. Refresh the page and try again to avoid overwriting newer changes."
    }.freeze

    PERMISSION_ERROR_PATTERNS = [
      /error executing cel program.*blocked authorization/,
      /unauthorized|forbidden|permission denied/i,
      /error executing cel program: invalid subject for user authentication/i
    ].freeze

    DEFAULT_ERROR_MESSAGE = "Internal server error."

    # Exact match, not a substring: OpenBao's own error bodies also say "not
    # found" for faults that must keep reporting, such as "route entry not
    # found", which means the path is not mounted at all.
    NOT_FOUND_ERROR_MESSAGE = "not found"

    # OpenBao quotes the requested path in its own error text, and that path
    # ends in a user-chosen secret name.
    QUOTED_PATH_PATTERN = /"[^"]*"/
    REDACTED_PATH = '"[REDACTED]"'

    def permission_error?(error_message)
      return false if error_message.blank?

      PERMISSION_ERROR_PATTERNS.any? { |pattern| error_message.match?(pattern) }
    end

    def not_found_error?(error_message)
      error_message == NOT_FOUND_ERROR_MESSAGE
    end

    def default_error?(error_message)
      error_message == DEFAULT_ERROR_MESSAGE
    end

    def sanitize_error_message(error_message)
      return DEFAULT_ERROR_MESSAGE if error_message.blank?

      ERROR_MAPPINGS.each do |pattern, user_message|
        return user_message if error_message.match?(pattern)
      end

      DEFAULT_ERROR_MESSAGE
    end

    def redact_paths(error_message)
      error_message.to_s.gsub(QUOTED_PATH_PATTERN, REDACTED_PATH)
    end

    # A copy, because an exception message cannot be mutated and nothing
    # downstream redacts one: Gitlab::Sanitizers::ExceptionMessage only rewrites
    # URI errors. Same class and backtrace, so Sentry keeps a usable stack.
    def redacted_exception(error)
      redacted = error.class.new(redact_paths(error.message))
      redacted.set_backtrace(error.backtrace) if error.backtrace

      redacted
    end
  end
end
