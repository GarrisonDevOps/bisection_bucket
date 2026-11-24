# frozen_string_literal: true

module Gitlab
  module GrapeOpenapi
    module Converters
      class PathConverter
        # Grape stores response-entity declarations under :entity (when declared
        # via `entity:` on the route) and :success (when declared via the `success`
        # DSL inside a `desc` block, in any of its forms). EntityConverter.register
        # handles all three shapes (Class, Hash with :model, Array of those).
        RESPONSE_DECLARATIONS = %i[entity success].freeze

        # A Grape optional path segment: a parenthesised group, e.g. `(/:id)`.
        # A backslash-escaped paren is a literal character, not a group - OData
        # routes use them, e.g. `nuget/v2/Packages\(Id='*package_name'\)`.
        OPTIONAL_SEGMENT = /(?<!\\)\(([^()]*)(?<!\\)\)/

        # The counterpart of OPTIONAL_SEGMENT: the parenthesis is a literal URL
        # character and only the backslash is Grape pattern syntax, so the escape
        # is dropped once optional segments have been resolved.
        ESCAPED_PAREN = /\\([()])/

        # Optional path segment variants are each represented in the OpenAPI spec as a unique path.
        PathVariant = Struct.new(:key, :path_override, :removed_params)

        def self.convert(routes, schema_registry, request_body_registry)
          new(routes, schema_registry, request_body_registry).convert
        end

        def initialize(routes, schema_registry, request_body_registry)
          @routes = routes
          @schema_registry = schema_registry
          @request_body_registry = request_body_registry
          @operation_id_registry = OperationIdRegistry.new
          @config = Gitlab::GrapeOpenapi.configuration
          @inherited_path_params = {}
        end

        def convert
          register_inherited_path_params

          paths = {}
          grouped_routes.each do |path_key, routes_for_path|
            path_variants(path_key, routes_for_path.first).each do |variant|
              paths[variant.key] ||= {}
              paths[variant.key].merge!(build_path_item(routes_for_path, variant))
            end
          end

          paths.reject { |_path, operations| operations.empty? }
        end

        private

        attr_reader :config, :routes, :schema_registry, :request_body_registry, :inherited_path_params

        def grouped_routes
          groups = {}

          routes.each do |route|
            next if skip_route?(route)

            register_route_entities(route)

            key = grouping_key(route)
            groups[key] ||= []
            groups[key] << route
          end

          groups.transform_keys { |key| normalize_path(groups[key].first) }
        end

        # Register entities declared on the route's response so they appear in
        # `components.schemas` only for routes that are actually emitted.
        # Running this after `skip_route?` keeps registration in sync with the
        # final spec and avoids `no-unused-components` orphans for entities
        # that belong only to hidden routes or wildcard catch-alls.
        def register_route_entities(route)
          RESPONSE_DECLARATIONS.each do |key|
            definition = route.options[key]
            next unless definition

            EntityConverter.register(definition, @schema_registry)
            register_schema_files(definition)
          end
        end

        def register_schema_files(definition)
          case definition
          when Hash
            return if EntityConverter.grape_entity?(definition[:model])

            @schema_registry.register_file(definition[:schema]) if definition[:schema]
          when Array then definition.each { |item| register_schema_files(item) }
          end
        end

        def skip_route?(route)
          # Hidden routes (declared with `hidden true`) must be skipped before
          # OperationConverter runs. Otherwise it pollutes the shared schema and
          # request-body registries with entries that no emitted operation references,
          # surfacing as `no-unused-components` warnings under `components.schemas`.
          return true if hidden?(route)

          # Grape's catch-all (`route :any, '*path'`) is an internal routing artifact,
          # not an API endpoint, and * isn't a valid HTTP method. Grape itself
          # discriminates it by request method - see `collect_route_config_per_pattern`
          # in `grape/api/instance.rb` - so match on the method alone.
          #
          # Do NOT also skip paths containing `*`. Splat segments are declared by
          # developers for path segments that may contain slashes (`*module_name`,
          # `*package_name`), and they are real endpoints. NormalizedPath renders them
          # as ordinary `{name}` placeholders. See issue #22.
          extract_method(route) == '*'
        end

        def hidden?(route)
          !!route.options.dig(:settings, :description, :hidden)
        end

        def normalize_path(route)
          NormalizedPath.new(route.pattern.origin).to_s.gsub('{version}', config.api_version)
        end

        def grouping_key(route)
          normalize_path(route).gsub(/\{[^}]+\}/, '{param}')
        end

        def build_path_item(routes_for_path, variant)
          path_item = Models::PathItem.new
          routes_by_method = routes_for_path.group_by { |route| extract_method(route) }
            .transform_values(&:last)

          routes_by_method.each_value do |route|
            operation = OperationConverter.convert(
              route,
              schema_registry,
              request_body_registry,
              inherited_path_params: inherited_path_params,
              path_override: variant.path_override,
              removed_params: variant.removed_params,
              operation_id_registry: @operation_id_registry
            )
            method = extract_method(route)
            path_item.add_operation(method, operation)
          end

          path_item.to_h
        end

        # Expand a grouped path key into the OpenAPI paths it maps to.
        #
        # A single OpenAPI path key cannot express Grape's optional segments,
        # so a route with one param-bearing optional segment fans out into two
        # keys: a collapsed variant (segment and param removed entirely) and an
        # expanded variant (param present, rendered as a required path param).
        # Routes without such a segment yield a single, unchanged variant.
        #
        # Both variants resolve *every* optional group, not just the
        # param-bearing one, because a route can put the separator in a group of
        # its own: `releases/permalink/latest(/)(*suffix_path)` needs the `(/)`
        # dropped alongside the param and inlined alongside it, or the expanded
        # key would read `latest(/){suffix_path}` and match no real URL.
        #
        # Every emitted key drops the backslash of an escaped parenthesis, which
        # can only happen once optional segments are resolved: until then it is
        # the escape that tells a literal parenthesis apart from a group.
        def path_variants(path_key, route)
          param_groups = path_key.scan(OPTIONAL_SEGMENT).flatten.select { |inner| inner.match?(/\{\w+\}/) }

          raise MultipleOptionalSegmentsError, multi_segment_message(route, path_key) if param_groups.length > 1

          inner = param_groups.first
          return [PathVariant.new(unescape_parens(path_key), nil, [])] if inner.nil?

          removed = inner.scan(/\{(\w+)\}/).flatten
          collapsed = unescape_parens(squeeze_slashes(path_key.gsub(OPTIONAL_SEGMENT, '')).delete_suffix('/'))
          collapsed = '/' if collapsed.empty?
          expanded = unescape_parens(squeeze_slashes(path_key.gsub(OPTIONAL_SEGMENT) { Regexp.last_match(1) }))

          [
            PathVariant.new(collapsed, collapsed, removed),
            PathVariant.new(expanded, expanded, [])
          ]
        end

        def squeeze_slashes(path)
          path.gsub(%r{//+}, '/')
        end

        def unescape_parens(path)
          path.gsub(ESCAPED_PAREN) { Regexp.last_match(1) }
        end

        def multi_segment_message(route, path_key)
          "Route '#{extract_method(route)} #{path_key}' declares more than one optional path segment " \
            "with a named parameter. gitlab-grape-openapi supports at most one optional segment per route " \
            "and does not generate the combinatorial set of path variants."
        end

        def extract_method(route)
          route.request_method
        end

        # Index every declared path placeholder by the path prefix that
        # introduces it, so a route that does not declare a placeholder
        # itself can still inherit the declaration from a sibling route
        # (e.g. a mounted child route inheriting `:id` from its mount
        # parent, where Grape drops the parent's `requires :id` from the
        # child route's own `options[:params]`).
        def register_inherited_path_params
          routes.each do |route|
            next if skip_route?(route)

            declared = route.options[:params] || {}
            next if declared.empty?

            segments = normalize_path(route).split('/')

            declared.each do |placeholder_name, param_options|
              placeholder_pattern = "{#{placeholder_name}}"
              idx = segments.index(placeholder_pattern)
              next unless idx

              prefix = segments[0..idx].join('/')
              inherited_path_params[[prefix, placeholder_name]] ||= param_options
            end
          end
        end
      end
    end
  end
end
