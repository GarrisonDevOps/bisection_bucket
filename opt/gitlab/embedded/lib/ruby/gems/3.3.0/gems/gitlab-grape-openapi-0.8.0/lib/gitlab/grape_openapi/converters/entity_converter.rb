# frozen_string_literal: true

module Gitlab
  module GrapeOpenapi
    module Converters
      class EntityConverter
        include Concerns::Serializable

        attr_reader :entity_class, :schema_registry

        OBJECT_TYPE = 'object'
        ARRAY_TYPE = 'array'
        DEFAULT_TYPE = 'string'
        REF_KEY = '$ref'
        SCHEMA_PATH_PREFIX = '#/components/schemas/'

        def self.register(entity, schema_registry)
          case entity
          when Class
            return unless grape_entity?(entity)

            new(entity, schema_registry).convert
          when Hash
            return unless entity[:model] && grape_entity?(entity[:model])

            new(entity[:model], schema_registry).convert
          when Array
            # Array elements may be Class (`success [Entities::Foo]`) or
            # Hash-with-:model (`success [{ code:, model: Foo }]`). Recurse so
            # both are registered. Mirrors `ResponseConverter`'s handling.
            entity.each { |item| register(item, schema_registry) }
          end
        end

        def self.grape_entity?(klass)
          klass.is_a?(Class) && klass.ancestors.include?(Grape::Entity)
        end

        def initialize(entity_class, schema_registry)
          @entity_class = entity_class
          @schema_registry = schema_registry
        end

        def convert(register: true)
          normalized_name = schema_registry.normalize_entity_class(entity_class)
          return schema_registry.schemas[normalized_name] if schema_registry.schemas.key?(normalized_name)

          schema = build_schema
          schema_registry.register(entity_class, schema) if register
          schema
        end

        private

        def build_schema
          Models::Schema.new.tap do |schema|
            schema.type = OBJECT_TYPE
            schema.properties = build_exposures_properties(root_exposures)

            required = required_exposure_keys(root_exposures)
            schema.required = required if required.any?
          end
        end

        def required_exposure_keys(exposures)
          exposures.flat_map do |exposure|
            if inlineable_merge_exposure?(exposure)
              # Merged entity properties become the parent's, so their
              # `required` entries do too.
              build_or_fetch_nested_schema(nested_entity_class(exposure))&.required || []
            elsif block_exposure?(exposure) && exposure.for_merge
              required_exposure_keys(exposure.nested_exposures)
            elsif exposure_documentation(exposure)[:required]
              [exposure.key.to_s]
            else
              []
            end
          end.uniq
        end

        def build_exposures_properties(exposures)
          exposures.each_with_object({}) do |exposure, properties|
            if inlineable_merge_exposure?(exposure)
              # `merge: true` flattens the nested entity's exposures into the
              # parent at runtime. Inline its properties instead of emitting a
              # `$ref`, so the generated schema reflects the actual response.
              inline_merged_properties!(properties, exposure)
            elsif block_exposure?(exposure)
              add_block_exposure_properties!(properties, exposure)
            else
              properties[exposure.key] = build_property(exposure)
            end
          end
        end

        # Grouping blocks (`expose :foo do ... end`) are NestingExposure
        # instances. Blocks that compute a value (`expose(:foo) { |obj, _| }`)
        # are BlockExposure and fall through to the default handling.
        def block_exposure?(exposure)
          exposure.is_a?(Grape::Entity::Exposure::NestingExposure)
        end

        def add_block_exposure_properties!(properties, exposure)
          if exposure.for_merge
            # A `merge: true` block merges its nested hash into the parent at
            # runtime, so its key never appears in the response.
            properties.merge!(build_exposures_properties(exposure.nested_exposures))
          else
            properties[exposure.key] = build_block_property(exposure)
          end
        end

        def build_block_property(exposure)
          documentation = exposure_documentation(exposure)
          nested_properties = build_exposures_properties(exposure.nested_exposures)
          object_schema = { type: OBJECT_TYPE }
          object_schema[:properties] = nested_properties if nested_properties.any?

          nested_required = required_exposure_keys(exposure.nested_exposures)
          object_schema[:required] = nested_required if nested_required.any?

          if documentation[:is_array]
            { type: ARRAY_TYPE, description: documentation[:desc], items: object_schema }.compact
          else
            object_schema.merge(description: documentation[:desc]).compact
          end
        end

        def inlineable_merge_exposure?(exposure)
          return false unless exposure.for_merge

          nested = nested_entity_class(exposure)
          nested.is_a?(Class) && self.class.grape_entity?(nested)
        end

        def inline_merged_properties!(properties, exposure)
          nested_schema = build_or_fetch_nested_schema(nested_entity_class(exposure))
          return unless nested_schema&.properties

          # Grape Entity's `merge: true` lets later exposures override earlier
          # ones with the same key, so merging into `properties` mirrors that.
          properties.merge!(nested_schema.properties)
        end

        # Build the merged entity's schema without registering it as a
        # standalone component. Entities only reached through `merge: true` are
        # inlined into their parents and do not need their own component entry.
        # `convert` still returns an already-registered schema when one exists
        # (for entities also reached via a regular `using:` elsewhere), and
        # `build_schema` still walks nested `using:` exposures, so any schema
        # actually referenced by `$ref` remains registered.
        def build_or_fetch_nested_schema(nested_class)
          self.class.new(nested_class, schema_registry).convert(register: false)
        end

        def build_property(exposure)
          property = extract_basic_attributes(exposure)
          apply_type_specific_attributes!(property, exposure)
          property.compact
        end

        def extract_basic_attributes(exposure)
          documentation = exposure_documentation(exposure)
          default_value = exposure_default(exposure)

          type = documentation[:type]

          if multiple_types?(type)
            build_one_of_property(type, documentation, default_value)
          else
            build_single_type_property(type, documentation, default_value)
          end
        end

        def multiple_types?(type)
          type.is_a?(Array) && type.length > 1
        end

        def build_one_of_property(types, documentation, default_value)
          members = types.map { |type| build_type_schema(type, documentation) }

          TypeResolver.union_schema(members).merge(
            description: documentation[:desc],
            default: stringify_symbols(default_value),
            example: stringify_symbols(documentation[:example])
          )
        end

        def build_single_type_property(type, documentation, default_value)
          # Handle single element arrays
          actual_type = type.is_a?(Array) ? type.first : type

          {
            type: TypeResolver.resolve_type(actual_type) || DEFAULT_TYPE,
            description: documentation[:desc],
            format: TypeResolver.resolve_format(documentation[:format], actual_type),
            enum: enum_values(documentation),
            default: stringify_symbols(default_value),
            example: stringify_symbols(documentation[:example])
          }
        end

        # `values:` may also be a Proc or a Range (runtime validation
        # constructs); only a literal Array translates to a fixed OpenAPI
        # enum. Mirrors `ParameterConverter#build_enum_schema`. Symbols are
        # stringified because the response contains strings, not symbols.
        def enum_values(documentation)
          values = documentation[:values]
          return unless values.is_a?(Array) && values.any?

          stringify_symbols(values)
        end

        def build_type_schema(type, documentation)
          schema = { type: TypeResolver.resolve_type(type) || DEFAULT_TYPE }

          format = TypeResolver.resolve_format(documentation[:format], type)
          schema[:format] = format if format

          schema
        end

        def apply_type_specific_attributes!(property, exposure)
          # Skip type-specific handling for oneOf properties
          return if property[:oneOf]

          if array_exposure?(exposure)
            handle_array_property!(property, exposure)
          elsif nested_entity?(exposure)
            handle_entity_reference!(property, exposure)
          end
        end

        def handle_array_property!(property, exposure)
          if nested_entity?(exposure)
            register_nested_entity(exposure)
            reference = build_reference(exposure)
            set_array_property!(property, reference)
          else
            set_array_primitive_property!(property)
          end
        end

        def handle_entity_reference!(property, exposure)
          register_nested_entity(exposure)
          reference = build_reference(exposure)
          set_reference_property!(property, reference)
        end

        # Ensure schemas reachable from a route via nested `using:` exposures are
        # registered too, so dropping the over-broad `Grape::Entity.descendants`
        # seed in the generator does not leave dangling `$ref`s.
        def register_nested_entity(exposure)
          nested = nested_entity_class(exposure)
          return unless nested.is_a?(Class)

          self.class.register(nested, schema_registry)
        end

        def set_array_primitive_property!(property)
          item_type = property[:type] || DEFAULT_TYPE
          property[:type] = ARRAY_TYPE
          property[:items] = build_primitive_items(property, item_type)
        end

        def build_primitive_items(property, item_type)
          items = { type: item_type }

          # Move format and enum to items if present; they constrain each
          # element, not the array itself
          [:format, :enum].each do |key|
            next unless property[key]

            items[key] = property[key]
            property[key] = nil
          end

          items
        end

        def set_array_property!(property, reference)
          property[:type] = ARRAY_TYPE
          property[:items] = { REF_KEY => reference }
        end

        def set_reference_property!(property, reference)
          property[:type] = nil
          property[REF_KEY] = reference
        end

        def build_reference(exposure)
          entity_name = nested_entity_class(exposure)
          "#{SCHEMA_PATH_PREFIX}#{normalize_entity_name(entity_name)}"
        end

        def normalize_entity_name(entity_name)
          if entity_name.is_a?(Class)
            entity_name.name.delete(':')
          else
            entity_name.delete(':')
          end
        end

        def root_exposures
          entity_class.root_exposure.nested_exposures
        end

        def exposure_documentation(exposure)
          exposure.documentation || {}
        end

        # Grape Entity stores the `:default` option in `@default_value` but
        # does not expose a public reader for it. Reaching for the ivar is the
        # only way to read it without going through `send(:options)`, which the
        # `GitlabSecurity/PublicSend` rule disallows.
        def exposure_default(exposure)
          exposure.instance_variable_get(:@default_value)
        end

        def nested_entity?(exposure)
          !nested_entity_class(exposure).nil?
        end

        # Only `RepresentExposure` instances (i.e. exposures declared with
        # `using:`) expose a `using_class_name` reader; for any other exposure
        # type there is no nested entity to reference.
        def nested_entity_class(exposure)
          return unless exposure.respond_to?(:using_class_name)

          exposure.using_class_name
        end

        def array_exposure?(exposure)
          exposure_documentation(exposure)[:is_array]
        end
      end
    end
  end
end
