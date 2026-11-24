# frozen_string_literal: true

module Gitlab
  module Database
    module LoadBalancing
      # A PostgreSQL LSN, compared in Ruby when a database query is not an option.
      class Lsn < Data.define(:text, :value)
        include Comparable

        # Accepts what PostgreSQL accepts, see
        # https://github.com/postgres/postgres/blob/d6bf0ab/src/common/pg_parse_lsn.c
        FORMAT = %r{\A(\h{1,8})/(\h{1,8})\z}

        # An LSN is two hexadecimal numbers, the high and low 32 bits, such as "16/B374D848".
        def self.parse(text)
          high, low = FORMAT.match(text.to_s)&.captures

          new(text, (high.to_i(16) << 32) + low.to_i(16)) if high
        end

        def <=>(other)
          value <=> other.value if other.is_a?(self.class)
        end

        def to_s
          text
        end
      end
    end
  end
end
