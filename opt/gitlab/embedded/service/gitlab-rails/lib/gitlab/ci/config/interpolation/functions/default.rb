# frozen_string_literal: true

module Gitlab
  module Ci
    class Config
      module Interpolation
        module Functions
          class Default < Base
            def self.function_expression_pattern
              /^#{name}\((?:'(?<literal>[^']*)'|(?<access>[\w.\[\]-]+))\)$/
            end

            def self.name
              'default'
            end

            def execute(input_value)
              fallback = function_args[:literal] || fallback_from_access
              return unless valid?

              # String inputs coerce nil to "", so treating only nil as empty would never apply to them.
              input_value.nil? || input_value == '' ? fallback : input_value
            end

            private

            # Resolved even when the value is present, so a wrong field fails for every ref, not only unreleased ones.
            def fallback_from_access
              access = Interpolation::Access.new(function_args[:access], ctx)
              return access.value if access.valid?

              access.errors.each { |message| error("invalid argument: #{message}") }
            end
          end
        end
      end
    end
  end
end
