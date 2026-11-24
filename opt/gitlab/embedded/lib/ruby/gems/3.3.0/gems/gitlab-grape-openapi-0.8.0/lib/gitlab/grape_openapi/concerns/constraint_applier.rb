# frozen_string_literal: true

# Applies the `values:` and `default:` parameter constraints to an already-built schema.

module Gitlab
  module GrapeOpenapi
    module Concerns
      module ConstraintApplier
        include Serializable

        private

        # values: on an array-typed parameter constrains each element, so it belongs
        # on items.enum rather than on the array schema itself.
        def apply_array_enum!(schema, values)
          return unless schema[:type] == 'array' && schema[:items].is_a?(Hash)
          return unless values.is_a?(Array)

          schema[:items][:enum] = stringify_symbols(values)
        end

        def apply_default!(schema, default, example: nil)
          return if default.nil?

          members = schema[:oneOf] || schema[:anyOf]
          return apply_union_default!(members, default) if members

          value = resolve_default(default, example: example)
          schema[:default] = value unless value.nil?
        end

        # `example` is unused here; ParameterConverter overrides this to feed it to its time serializer.
        def resolve_default(default, example: nil) # rubocop:disable Lint/UnusedMethodArgument -- overridden
          return unless serializable?(default)

          stringify_symbols(default)
        end

        # When a union (oneOf) schema has a `default:`, attach it to every member
        # whose schema can accept the default value. For arrays this includes
        # checking the items type so `[1, 2]` lands on `items: { type: integer }`
        # but not on `items: { type: string }`. Empty arrays are type-agnostic
        # and attach to all array members.
        def apply_union_default!(members, default)
          return unless serializable?(default)

          members.each do |member|
            member[:default] = stringify_symbols(default) if member_accepts_default?(member, default)
          end
        end

        def member_accepts_default?(member, default)
          case member[:type]
          when 'integer' then default.is_a?(Integer)
          when 'number'  then default.is_a?(Numeric)
          when 'boolean' then [true, false].include?(default)
          when 'string'  then default.is_a?(String) || default.is_a?(Symbol)
          when 'array'   then array_member_accepts?(member, default)
          when 'object'  then default.is_a?(Hash)
          end
        end

        def array_member_accepts?(member, default)
          return false unless default.is_a?(Array)
          return true if default.empty?

          item_type = member.dig(:items, :type)
          default.all? { |element| openapi_type_accepts?(item_type, element) }
        end

        def openapi_type_accepts?(openapi_type, value)
          case openapi_type
          when 'integer' then value.is_a?(Integer)
          when 'number'  then value.is_a?(Numeric)
          when 'boolean' then [true, false].include?(value)
          when 'string'  then value.is_a?(String) || value.is_a?(Symbol)
          else true
          end
        end
      end
    end
  end
end
