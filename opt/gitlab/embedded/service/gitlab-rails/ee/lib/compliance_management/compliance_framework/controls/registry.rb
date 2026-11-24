# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    module Controls
      class Registry
        CONTROL_TYPES = {
          boolean: { type: :boolean, valid_operators: ['=', '!='] },
          numeric: { type: :number, valid_operators: ['=', '!=', '>', '<', '>=', '<='] },
          enum: { type: :string, valid_operators: ['=', '!='] }
        }.freeze

        SPECIAL_CONTROLS = {
          external_control: 10000
        }.freeze

        class << self
          def controls
            @controls ||= load_registry
          end

          def validate_registry!
            RegistryValidator.validate!(controls, SPECIAL_CONTROLS)
          end

          def find_by_name(name)
            control_data = controls[name.to_sym]
            return {} unless control_data

            { id: name.to_sym }.merge(control_data)
          end

          def find_by_field_id(field_id)
            field_id = field_id.to_sym
            id, data = controls.find do |control_id, control_data|
              (control_data[:field_id] || control_id).to_sym == field_id
            end

            return {} unless id && data

            { id: id }.merge(data)
          end

          def default_operator_for_control(control)
            control[:compliant_operator] || '='
          end

          def valid_operators_for_field(field_id)
            control = find_by_field_id(field_id)
            return ['='] if control.empty?

            control[:type][:valid_operators]
          end

          def enum_definitions
            controls.transform_values { |data| data[:enum_value] }.merge(SPECIAL_CONTROLS)
          end

          def field_mappings
            controls.each_with_object({}) do |(id, data), hash|
              field_id = data[:field_id] || id

              field_method = data[:field_method]
              field_method = field_method.to_sym if field_method.is_a?(String)
              hash[field_id.to_s] = field_method
            end
          end

          def schema_fields
            controls.map do |id, data|
              field_id = data[:field_id] || id
              field_id.to_s
            end.uniq
          end

          def schema_field_types
            result = {}
            controls.each do |id, data|
              type = data[:type][:type]
              result[type] ||= []
              result[type] << { id: id }.merge(data)
            end
            result
          end

          def schema_enum_values
            result = {}
            controls.each do |id, data|
              next unless data[:type][:type] == :string && data[:valid_values]

              field_id = data[:field_id] || id
              result[field_id] = data[:valid_values]
            end
            result
          end

          def generate_schema
            SchemaGenerator.generate
          end

          def control_definitions
            controls.map do |id, data|
              field_id = data[:field_id] || id
              {
                id: id.to_s,
                name: data[:name],
                expression: {
                  field: field_id.to_s,
                  operator: data[:compliant_operator] || "=",
                  value: data[:compliant_value]
                }
              }
            end
          end

          private

          def load_registry
            yaml_path = Rails.root.join("ee/config/compliance_management/compliance_controls.yml")

            unless File.exist?(yaml_path)
              raise "Compliance controls YAML file not found at #{yaml_path}. " \
                "This file is required for defining compliance controls."
            end

            registry_data = YAML.safe_load(File.read(yaml_path),
              symbolize_names: true,
              permitted_classes: [Symbol])
            process_registry_data(registry_data[:controls])
          end

          def process_registry_data(controls_data)
            raise "Invalid or empty controls data in YAML file" unless controls_data&.any?

            result = {}
            controls_data.each do |id, control_data|
              type_name = control_data[:type]
              control_data[:type] = CONTROL_TYPES[type_name.to_sym]

              if control_data[:field_method].is_a?(String)
                control_data[:field_method] =
                  control_data[:field_method].to_sym
              end

              result[id] = control_data
            end

            result.freeze
          end
        end
      end
    end
  end
end
