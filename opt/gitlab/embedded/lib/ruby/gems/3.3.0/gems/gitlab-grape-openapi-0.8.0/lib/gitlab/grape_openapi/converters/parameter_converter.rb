# frozen_string_literal: true

module Gitlab
  module GrapeOpenapi
    module Converters
      class ParameterConverter
        include CoercerResolver
        include Concerns::ConstraintApplier
        include Concerns::LimitResolver
        include Concerns::FailFastAnnotatable
        include Concerns::RegexConverter
        include Concerns::Nullability

        attr_reader :name, :options, :validations, :route

        def self.convert(name, options:, route:, validations: [])
          new(name, options: options, validations: validations, route: route).convert
        end

        def initialize(name, options:, validations:, route:)
          @name = name
          @options = options
          @validations = validations
          @route = route # Useful for detecting `in` value.
        end

        def in_value
          path_parameter_names.include?(name.to_s) ? 'path' : 'query'
        end

        def example
          @options.dig(:documentation, :example)
        end

        def coercer_mapping
          @coercer_mapping ||= coercer_mapping_for(validations)
        end

        def schema
          object_type = TypeResolver.resolve_type(options[:type]) || 'string'
          object_format = TypeResolver.resolve_format(nil, options[:type])
          type_str = options[:type].to_s

          mapping = coercer_mapping
          built_schema = if mapping
                           build_coerced_schema(mapping)
                         elsif type_str.start_with?('[') && type_str.exclude?(',')
                           build_simple_array_schema
                         elsif type_str.start_with?('[')
                           build_union_schema(object_type)
                         elsif options[:values].is_a?(Range)
                           build_range_schema(object_type)
                         elsif options[:values]
                           build_enum_schema(object_type)
                         elsif array_type?(object_type)
                           build_array_schema
                         else
                           build_basic_schema(object_type, object_format)
                         end

          apply_nullability!(built_schema, options, in_value: in_value)
          apply_limit!(built_schema, validations)
          apply_array_enum!(built_schema, options[:values])
          apply_default!(built_schema, options[:default], example: example)
          built_schema
        end

        def build_simple_array_schema
          item_type = options[:type].to_s.delete('[').delete(']')
          { type: 'array', items: { type: TypeResolver.resolve_type(item_type) } }
        end

        def build_union_schema(object_type)
          types = object_type[1..-2].split(", ")
          members = types.map { |type| TypeResolver.resolve_union_member(type) }
          schema = TypeResolver.union_schema(members)
          members = schema.values.first
          # Unlike `default:`, enum stays inline: it needs per-member type dispatch
          # (coercing values to each member's type) that a generic post-step cannot do.
          apply_union_enum!(members)
          schema
        end

        def build_range_schema(object_type)
          range = options[:values]
          schema = { type: object_type }

          schema[:minimum] = range.begin if range.begin
          schema[:maximum] = range.end if range.end
          schema
        end

        def build_enum_schema(object_type)
          schema = { type: object_type }
          schema[:enum] = stringify_symbols(options[:values]) unless options[:values].is_a?(Proc)
          schema
        end

        def build_array_schema
          item_type = extract_array_item_type
          { type: 'array', items: { type: item_type } }
        end

        def build_basic_schema(object_type, object_format)
          schema = { type: object_type }
          schema[:format] = object_format if object_format
          add_regex_validations!(schema)
          schema
        end

        def array_type?(object_type)
          object_type.include?('[')
        end

        def extract_array_item_type
          options[:type].delete('[').delete(']').downcase
        end

        def add_regex_validations!(schema)
          return unless validations

          # Only support one Regex validation per attribute
          validation = validations&.find { |v| v[:validator_class] == Grape::Validations::Validators::RegexpValidator }
          return unless validation

          pattern = regexp_to_pattern(validation[:options])
          schema[:pattern] = pattern if pattern
        end

        def convert
          # For requests that can have a request body (POST, PUT, PATCH, etc.), only return a param if it's in the path,
          # otherwise it'll be a body parameter and shouldn't be included as a query parameter.
          # GET and DELETE requests don't have request bodies, so all their parameters are included.
          method = route.request_method
          return nil if method != 'GET' && method != 'DELETE' && in_value != 'path'
          return nil if options.dig(:documentation, :hidden)

          annotated = options.dup
          if options[:desc] && fail_fast_in_validations?(validations)
            annotated[:desc] = annotate_fail_fast(options[:desc])
          end

          annotated[:desc] ||= route_param_desc

          param = Gitlab::GrapeOpenapi::Models::Parameter.new(
            name,
            options: annotated,
            schema: schema,
            in_value: in_value
          )

          mapping = coercer_mapping
          return param unless mapping

          param.style = mapping[:style] if mapping[:style]
          param.explode = mapping[:explode] if mapping.key?(:explode)
          param
        end

        private

        def path_parameter_names
          @path_parameter_names ||= NormalizedPath.new(route.origin).path_parameter_names
        end

        # Only path parameters can come from a `route_param`, and a same-named query
        # parameter must not pick its description up.
        def route_param_desc
          return unless in_value == 'path'

          GrapeCompat.route_param_desc(route, name)
        end

        def time_serializer
          @time_serializer ||= Serializers::Time.new
        end

        # When a union (oneOf) schema has a `values:` constraint, propagate it
        # as `enum` onto each oneOf member whose type can carry the values.
        # Skip Procs/Ranges to mirror build_enum_schema behavior.
        def apply_union_enum!(members)
          values = options[:values]
          return if values.nil? || values.is_a?(Proc) || values.is_a?(Range)

          members.each do |member|
            case member[:type]
            when 'integer'
              ints = values.select { |v| v.is_a?(Integer) }
              member[:enum] = ints if ints.any?
            when 'number'
              nums = values.select { |v| v.is_a?(Numeric) }
              member[:enum] = nums if nums.any?
            when 'string'
              member[:enum] = values.map(&:to_s)
            end
          end
        end

        # Checked before super because serializable? returns false for TimeWithZone.
        def resolve_default(default, example: nil)
          if defined?(ActiveSupport::TimeWithZone) && default.is_a?(ActiveSupport::TimeWithZone)
            return time_serializer.serialize(default, example: example)
          end

          super
        end
      end
    end
  end
end
