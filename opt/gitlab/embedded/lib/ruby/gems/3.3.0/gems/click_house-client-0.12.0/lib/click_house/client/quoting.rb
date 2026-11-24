# frozen_string_literal: true

module ClickHouse
  module Client
    module Quoting
      class << self
        def quote(value)
          case value
          when Numeric then value.to_s
          when String, Symbol then "'#{value.to_s.gsub('\\', '\&\&').gsub("'", "''")}'"
          when Array then "[#{value.map { |v| quote(v) }.join(',')}]"
          when Time then value.utc.to_f
          when nil then "NULL"
          else quote_str(value.to_s)
          end
        end

        private

        def quote_str(value)
          "'#{value.gsub("'", "''")}'"
        end
      end
    end
  end
end
