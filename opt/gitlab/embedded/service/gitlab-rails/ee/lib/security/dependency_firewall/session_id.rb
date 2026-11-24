# frozen_string_literal: true

module Security
  module DependencyFirewall
    # Drops a non-conforming value rather than truncating or stripping it: either could merge two
    # distinct invocations into one group, and a false grouping is worse than no attribution.
    module SessionId
      MAX_LENGTH = 255
      PATTERN = /\A[\w-]+\z/

      class << self
        def sanitize(value)
          # The bytesize gate is O(1) and safe: only ASCII can match PATTERN, so nothing over
          # MAX_LENGTH bytes could have conformed, and Rack accepts far larger headers than this.
          return unless value.is_a?(String) && value.bytesize <= MAX_LENGTH
          # Both guards keep the regex match from raising: it raises on a non-ASCII-compatible
          # encoding and on broken bytes. Neither guard allocates.
          return unless value.encoding.ascii_compatible? && value.valid_encoding?

          value if PATTERN.match?(value)
        end
      end
    end
  end
end
