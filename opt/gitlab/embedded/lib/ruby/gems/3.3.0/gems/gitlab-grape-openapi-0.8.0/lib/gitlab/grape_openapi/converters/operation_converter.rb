# frozen_string_literal: true

module Gitlab
  module GrapeOpenapi
    module Converters
      class OperationConverter
        # https://github.com/OAI/OpenAPI-Specification/blob/main/versions/3.0.0.md#operation-object

        DASH_SEGMENT = 'Dash'

        def self.convert(
          route, schema_registry, request_body_registry, inherited_path_params: {},
          path_override: nil, removed_params: [], operation_id_registry: nil)
          new(
            route,
            schema_registry,
            request_body_registry,
            inherited_path_params: inherited_path_params,
            path_override: path_override,
            removed_params: removed_params,
            operation_id_registry: operation_id_registry
          ).convert
        end

        def initialize(
          route, schema_registry, request_body_registry, inherited_path_params: {},
          path_override: nil, removed_params: [], operation_id_registry: nil)
          @route = route
          @schema_registry = schema_registry
          @request_body_registry = request_body_registry
          @operation_id_registry = operation_id_registry
          @inherited_path_params = inherited_path_params
          # @path_override and @removed_params are set together when optional-path-segment variants exist
          @path_override = path_override
          @removed_params = removed_params
          @config = Gitlab::GrapeOpenapi.configuration
          @options = route.options
          @pattern = route.pattern
          @endpoint = route.app
        end

        def convert
          id = operation_id_registry ? operation_id_registry.register(operation_id) : operation_id

          Models::Operation.new.tap do |operation|
            operation.operation_id = id
            operation.summary = extract_description
            operation.description = annotate_oversized_constraints(extract_detail)
            operation.tags = extract_tags
            operation.deprecated = extract_deprecated
            operation.hidden = extract_hidden
            operation.parameters = extract_parameters
            operation.responses = ResponseConverter.new(@route, @schema_registry).convert
            operation.request_body = extract_request_body(id) || {}
            operation.annotations = extract_annotations
          end
        end

        private

        attr_reader :config, :route, :options, :pattern, :endpoint, :schema_registry, :request_body_registry,
          :inherited_path_params, :path_override, :removed_params, :operation_id_registry

        def route_method
          @route.request_method
        end

        def extract_annotations
          return {} unless options[:settings]

          selected_keys = options[:settings].keys.select do |k|
            config.annotations.key?(k)
          end

          selected_keys.to_h do |key|
            [config.annotations[key], options[:settings][key].to_s]
          end
        end

        def extract_parameters
          params = if options[:params].empty?
                     []
                   else
                     options[:params].filter_map do |key, param_options|
                       Converters::ParameterConverter.convert(
                         key,
                         options: annotate_constraint(key, param_options),
                         validations: validations_for(key.to_sym),
                         route: route
                       )
                     end
                   end

          params = inject_missing_path_parameters(params)
          return params if removed_params.empty?

          removed = removed_params.map(&:to_s)
          params.reject { |param| removed.include?(param.name.to_s) }
        end

        def annotate_constraint(key, param_options)
          note = cross_field_notes[key.to_s]
          return param_options unless note

          param_options.merge(desc: Converters::CrossFieldValidationResolver.append_note(param_options[:desc], note))
        end

        # Per-param cross-field constraint notes to fold into descriptions, e.g.
        #   { 'author_id' => 'Mutually exclusive with `author_username`.' }.
        # Keyed by the full bracketed param name, so a nested-Hash query filter
        # (`not[author_id]`, which Grape flattens into `options[:params]`) is
        # annotated the same way a top-level param is.
        def cross_field_notes
          cross_field_resolver.notes
        end

        # Built over every declared param, body ones included, so an oversized
        # group is found even when its members document a request body.
        def cross_field_resolver
          @cross_field_resolver ||=
            Converters::CrossFieldValidationResolver.new(route, options[:params].keys.map(&:to_s))
        end

        # A group too large to enumerate is stated once on the operation rather
        # than on every member.
        def annotate_oversized_constraints(description)
          oversized = cross_field_resolver.oversized
          return description if oversized.empty?

          message = configured_message
          report_oversized_constraints(oversized) unless message
          sentences = message ? [message] : oversized.map { |group| group[:summary] }.uniq

          sentences.reduce(description) do |text, sentence|
            Converters::CrossFieldValidationResolver.append_note(text, sentence)
          end
        end

        # A blank entry counts as absent. Left as-is it would satisfy the
        # `unless message` guard, silencing the sentence and the warning together
        # and leaving the constraint undocumented with nothing to show for it.
        def configured_message
          message = config.cross_field_messages[endpoint_key]
          message unless message.to_s.strip.empty?
        end

        def report_oversized_constraints(oversized)
          return unless config.warnings

          oversized.each do |group|
            warn "[gitlab-grape-openapi] oversized cross-field constraint: " \
              "#{endpoint_key} params=#{group[:size]} " \
              "(limit #{config.cross_field_group_limit}, using generic sentence)"
          end
        end

        # Keyed on the route's own path rather than `normalized_path`. Matches the
        # string the warnings print, so stderr says what to put in the config.
        def endpoint_key
          "#{http_method} #{normalize_path_pattern}"
        end

        def inject_missing_path_parameters(params)
          declared_names = params.map(&:name).to_set

          path_placeholders = normalized_path.scan(/\{(\w+)\}/).flatten
          path_segments = normalized_path.split('/')

          path_placeholders.each do |placeholder|
            next if declared_names.include?(placeholder)

            inherited = lookup_inherited_param(path_segments, placeholder)

            params << if inherited
                        ParameterConverter.convert(
                          placeholder,
                          options: inherited,
                          route: route
                        )
                      else
                        # Empty schema because no declaration was found locally or in any
                        # sibling route's path prefix. Valid OpenAPI 3.0 ("any type") but
                        # incomplete; report the offender to stderr so callers can fix
                        # it in source.
                        report_synthesized_parameter(placeholder)
                        Models::Parameter.new(
                          placeholder,
                          options: { required: true },
                          schema: {},
                          in_value: 'path'
                        )
                      end
          end

          params
        end

        # Emit a one-line stderr warning identifying the route and API
        # class responsible for a `schema: {}` entry in the generated spec.
        # Disabled by default and gated behind `config.warnings` so it does
        # not pollute stderr in callers that treat any warning output as a
        # failure (e.g. GitLab's `fail_on_warnings` static-analysis wrapper).
        # The output is grep-friendly: each line starts with the literal
        # `[gitlab-grape-openapi]` tag and includes the HTTP method, the
        # full normalized path, the placeholder name, and the API class
        # name. From the class name, the source file follows GitLab's
        # autoload conventions (`API::Foo::Bar` -> `lib/api/foo/bar.rb`).
        def report_synthesized_parameter(placeholder)
          return unless config.warnings

          api_class = route.app.options[:for] if route.app.respond_to?(:options)
          warn "[gitlab-grape-openapi] synthesized path param: " \
            "#{http_method} #{normalized_path} placeholder=:#{placeholder} " \
            "class=#{api_class || 'unknown'}"
        end

        # Look up a path-prefix-keyed declaration so mounted child routes
        # can inherit `requires :id` (etc.) from the parent that mounted them.
        def lookup_inherited_param(path_segments, placeholder)
          idx = path_segments.index("{#{placeholder}}")
          return unless idx

          prefix = path_segments[0..idx].join('/')
          inherited_path_params[[prefix, placeholder]]
        end

        def operation_id
          method = http_method.downcase
          normalized = normalized_path
          segments = normalized.split('/').reject(&:empty?)

          parts = segments.filter_map do |seg|
            next DASH_SEGMENT if seg == '-'

            if seg.include?('{')
              camelize(seg.gsub(/\{[^}]+\}/) { |m| m[1..-2] })
            else
              camelize(seg)
            end
          end

          "#{method}#{parts.join}"
        end

        def extract_description
          description_from_options = options[:description]
          return description_from_options[:description] if description_from_options.is_a?(Hash)
          return description_from_options if description_from_options.is_a?(String)

          return unless endpoint

          description_hash = endpoint.inheritable_setting&.namespace
          description_hash[:description] if description_hash.is_a?(Hash)
        end

        def extract_detail
          options.dig(:settings, :description, :detail)
        end

        def extract_tags
          Array(@route.settings.dig(:description, :tags)).map do |tag|
            Gitlab::GrapeOpenapi::Models::Tag.normalize_tag_name(tag)
          end
        end

        def extract_deprecated
          !!options.dig(:settings, :description, :deprecated)
        end

        def extract_hidden
          !!options.dig(:settings, :description, :hidden)
        end

        def path_segments
          segments = normalized_path.split('/').reject do |segment|
            segment.empty? || segment.start_with?('{')
          end

          segments.reject { |seg| seg == config.api_prefix || seg == config.api_version || seg == '-' }
        end

        def normalized_path
          @normalized_path ||= path_override || normalize_path_pattern
        end

        def normalize_path_pattern
          NormalizedPath.new(pattern.origin).to_display_path(config.api_version)
        end

        def camelize(string)
          string.gsub(/[^a-zA-Z0-9_]/, '_').split('_').reject(&:empty?).map(&:capitalize).join
        end

        def http_method
          @route.request_method
        end

        # Get all validations for a single attribute
        # Looks something like:
        # [{:attributes=>[:version_prefix],
        #   :options=>/^[\d+.]+/,
        #   :opts=>{:fail_fast=>false},
        #   :validator_class=>Grape::Validations::Validators::RegexpValidator}]
        def validations_for(attribute)
          GrapeCompat.validations_for(route, attribute)
        end

        def extract_request_body(id)
          RequestBodyConverter.convert(
            route: route,
            options: options,
            params: options[:params],
            request_body_registry: request_body_registry,
            operation_id: id
          )
        end
      end
    end
  end
end
