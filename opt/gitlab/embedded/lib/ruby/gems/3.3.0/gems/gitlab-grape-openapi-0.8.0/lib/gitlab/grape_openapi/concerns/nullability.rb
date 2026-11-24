# frozen_string_literal: true

# Determines whether a param is nullable.
#
# Grape default behaviour sets nullability true for plain params.
# Two declarations remove it: a `default:`, which Grape's
# DefaultValidator substitutes for the null before the endpoint runs, and a path
# parameter, which is a required URL segment.
#
# The `minLength: 1` branch is mutually exclusive with nullability and stays coupled
# here deliberately: applying the two independently would mark every required enum
# nullable.
#
# NOTE: `param_options[:allow_blank]` is always nil. Grape omits allow_blank from
# route.params, so that clause is dead and only `required && values` fires.

module Gitlab
  module GrapeOpenapi
    module Concerns
      module Nullability
        private

        def apply_nullability!(schema, param_options, in_value: nil)
          if blank_rejected?(param_options)
            schema[:minLength] = 1 if schema[:type] == 'string'
          elsif nullable?(param_options, in_value)
            mark_nullable!(schema)
          end
        end

        def blank_rejected?(param_options)
          param_options[:allow_blank] == false ||
            (param_options[:required] && param_options[:values])
        end

        def nullable?(param_options, in_value)
          return false if in_value == 'path'

          param_options[:default].nil?
        end

        # Grape substitutes the default regardless of which union member matched, so
        # nullability applies to every member or none.
        def mark_nullable!(schema)
          members = schema[:oneOf] || schema[:anyOf]
          return members.each { |member| member[:nullable] = true } if members

          schema[:nullable] = true
        end
      end
    end
  end
end
