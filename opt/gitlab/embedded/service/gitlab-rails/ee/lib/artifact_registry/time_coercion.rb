# frozen_string_literal: true

module ArtifactRegistry
  # Shared ISO8601 timestamp coercion for AR API value objects.
  # Unparseable or non-string input coerces to nil rather than raising.
  module TimeCoercion
    private

    def parse_time(value)
      return unless value

      DateTime.iso8601(value)
    rescue ArgumentError, TypeError
      nil
    end
  end
end
