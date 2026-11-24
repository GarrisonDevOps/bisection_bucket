# frozen_string_literal: true

module Gitlab
  module GrapeOpenapi
    module Converters
      class RequestBodyConverter
        DEFAULT_CONTENT_TYPE = 'application/json'
        MULTIPART_FORM_DATA_CONTENT_TYPE = 'multipart/form-data'
        GET_METHOD = 'GET'
        DELETE_METHOD = 'DELETE'

        attr_reader :route, :options, :params, :request_body_registry, :operation_id

        def self.convert(route:, options:, params:, request_body_registry:, operation_id:)
          new(route: route, options: options, params: params, request_body_registry: request_body_registry,
            operation_id: operation_id).convert
        end

        def initialize(route:, options:, params:, request_body_registry:, operation_id:)
          @route = route
          @options = options
          @params = params
          @request_body_registry = request_body_registry
          @operation_id = operation_id
        end

        def convert
          return nil if route_method == GET_METHOD || route_method == DELETE_METHOD
          return nil if params.empty?

          body_params = Models::RequestBody::Parameters.new(route: route, params: params).extract
          return nil if body_params.empty?

          build_request_body(body_params)
        end

        private

        def route_method
          route.request_method
        end

        def build_request_body(body_params)
          properties = {}
          required_params = []

          body_params.each do |key, param_options|
            schema = Models::RequestBody::ParameterSchema.new(
              route: route, key: key, param_options: param_options
            ).build
            properties[key.to_s] = schema
            required_params << key.to_s if param_options[:required]
          end

          annotate_cross_field_constraints!(properties)

          schema = {
            type: 'object',
            properties: properties
          }
          schema[:required] = required_params unless required_params.empty?

          schema_ref = request_body_registry.register(schema, name: "#{operation_id}Request")

          {
            required: required_params.any?,
            content: {
              content_type(body_params) => {
                schema: schema_ref
              }
            }
          }
        end

        # Documents cross-field constraints (mutually_exclusive, ...) in each
        # affected property's description. OpenAPI has no cross-property keyword
        # and Scalar does not render JSON Schema `not` so the validation constraint
        # is expressed in prose.
        def annotate_cross_field_constraints!(properties)
          resolver = CrossFieldValidationResolver.new(route, properties.keys)

          resolver.notes.each do |name, note|
            property = properties[name]
            next unless property

            property[:description] = CrossFieldValidationResolver.append_note(property[:description], note)
          end

          warn_skipped_cross_field_constraints(resolver.skipped)
        end

        # Warns about a constraint we cannot document yet, because a member of the
        # group is not a property of this body. Usually the group is nested inside
        # an object property - GET/DELETE flatten such params into the query and
        # document them, POST/PUT/PATCH bodies keep the nesting - but a member
        # dropped from the body for another reason (a path param, or one hidden
        # with `documentation: { hidden: true }`) lands here too, hence the wording.
        def warn_skipped_cross_field_constraints(skipped)
          return unless config.warnings

          path = NormalizedPath.new(route.pattern.origin).to_display_path(config.api_version)
          skipped.each do |group|
            warn "[gitlab-grape-openapi] skipped cross-field constraint: " \
              "#{route_method} #{path} params=#{group.join(',')} (not a top-level body property)"
          end
        end

        def config
          @config ||= Gitlab::GrapeOpenapi.configuration
        end

        def content_type(body_params)
          custom_content_type = extract_consumes_content_type
          return custom_content_type if custom_content_type

          return MULTIPART_FORM_DATA_CONTENT_TYPE if allows_file_upload?(body_params)

          DEFAULT_CONTENT_TYPE
        end

        def extract_consumes_content_type
          consumes = route.settings.dig(:description, :consumes)
          return nil if consumes.blank?

          content_type = consumes.first
          content_type = DEFAULT_CONTENT_TYPE if content_type == :json
          content_type
        end

        def allows_file_upload?(body_params)
          body_params.any? do |_key, param_options|
            param_options[:type]&.include?('API::Validations::Types::WorkhorseFile')
          end
        end
      end
    end
  end
end
