# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    module Controls
      class SchemaGenerator
        class << self
          def generate
            schema = base_schema

            add_boolean_constraints(schema)
            add_numeric_constraints(schema)
            add_enum_constraints(schema)

            schema
          end

          private

          def base_schema
            all_operators = Registry::CONTROL_TYPES.values.flat_map { |t| t[:valid_operators] }.uniq

            {
              "$schema" => "http://json-schema.org/draft-07/schema#",
              "title" => "Compliance Requirements Control Expression Schema",
              "type" => "object",
              "properties" => {
                "field" => {
                  "type" => "string",
                  "enum" => Registry.schema_fields
                },
                "operator" => {
                  "type" => "string",
                  "enum" => all_operators
                },
                "value" => {
                  "type" => %w[string number boolean]
                }
              },
              "required" => %w[field operator value],
              "additionalProperties" => false,
              "allOf" => []
            }
          end

          def add_boolean_constraints(schema)
            boolean_fields = Registry.schema_field_types[:boolean]&.map { |c| (c[:field_id] || c[:id]).to_s } || []
            return if boolean_fields.empty?

            schema["allOf"] << {
              "if" => {
                "properties" => {
                  "field" => {
                    "enum" => boolean_fields
                  }
                }
              },
              "then" => {
                "properties" => {
                  "value" => {
                    "type" => "boolean"
                  },
                  "operator" => {
                    "enum" => Registry::CONTROL_TYPES[:boolean][:valid_operators]
                  }
                }
              }
            }
          end

          def add_numeric_constraints(schema)
            numeric_fields = Registry.schema_field_types[:number]&.map { |c| (c[:field_id] || c[:id]).to_s } || []
            return if numeric_fields.empty?

            schema["allOf"] << {
              "if" => {
                "properties" => {
                  "field" => {
                    "enum" => numeric_fields
                  }
                }
              },
              "then" => {
                "properties" => {
                  "value" => {
                    "type" => "number"
                  },
                  "operator" => {
                    "enum" => Registry::CONTROL_TYPES[:numeric][:valid_operators]
                  }
                }
              }
            }
          end

          def add_enum_constraints(schema)
            enum_values = Registry.schema_enum_values

            enum_values.each do |field, values|
              schema["allOf"] << {
                "if" => {
                  "properties" => {
                    "field" => {
                      "enum" => [field.to_s]
                    }
                  }
                },
                "then" => {
                  "properties" => {
                    "value" => {
                      "type" => "string",
                      "enum" => values
                    },
                    "operator" => {
                      "enum" => Registry::CONTROL_TYPES[:enum][:valid_operators]
                    }
                  }
                }
              }
            end
          end
        end
      end
    end
  end
end
