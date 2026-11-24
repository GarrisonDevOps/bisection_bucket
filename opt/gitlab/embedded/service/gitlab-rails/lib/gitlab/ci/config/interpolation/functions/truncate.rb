# frozen_string_literal: true

module Gitlab
  module Ci
    class Config
      module Interpolation
        module Functions
          class Truncate < Base
            def self.function_expression_pattern
              /^#{name}\(\s*(?<offset>\d+)\s*,\s*(?<length>\d+)\s*\)?$/
            end

            def self.name
              'truncate'
            end

            def execute(input_value)
              if input_value.is_a?(String)
                # String#[] raises RangeError for an Integer that does not fit in a C long.
                size = input_value.length
                input_value[offset.clamp(0, size), length.clamp(0, size)].to_s
              else
                error('invalid input type: truncate can only be used with string inputs')
                nil
              end
            end

            private

            def offset
              function_args[:offset].to_i
            end

            def length
              function_args[:length].to_i
            end
          end
        end
      end
    end
  end
end
