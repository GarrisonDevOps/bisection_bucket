# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    module Controls
      class RegistryValidator
        DUPLICATE_FIELD_IDS_ERROR = "Duplicate field IDs detected: %s. This would cause conflicts."
        DUPLICATE_ENUM_VALUES_ERROR = "Duplicate enum values detected within registry: %s"
        DUPLICATE_ENUM_VALUES_BETWEEN_REGISTRIES_ERROR =
          "Duplicate enum values detected between registry and special controls:\n" \
            "Registry controls (%s) conflict with special controls (%s)."

        RegistryValidationError = Class.new(StandardError)

        class << self
          def validate!(controls, special_controls)
            controls ||= {}
            special_controls ||= {}

            validate_field_ids!(controls)
            validate_enum_values!(controls, special_controls)
            true
          end

          private

          def validate_field_ids!(controls)
            field_ids = controls.map { |id, data| data[:field_id] || id }
            duplicates = find_duplicates(field_ids)

            return unless duplicates.any?

            raise RegistryValidationError, format(DUPLICATE_FIELD_IDS_ERROR, duplicates.join(', '))
          end

          def validate_enum_values!(controls, special_controls)
            registry_enum_values = controls.values.filter_map { |data| data[:enum_value] }
            special_control_values = special_controls.values

            conflicts = registry_enum_values & special_control_values
            if conflicts.any?
              registry_conflicts = find_control_names(controls, conflicts, :enum_value)
              special_conflicts = find_control_names(special_controls, conflicts)

              raise RegistryValidationError,
                format(DUPLICATE_ENUM_VALUES_BETWEEN_REGISTRIES_ERROR, registry_conflicts, special_conflicts)
            end

            registry_duplicates = find_duplicates(registry_enum_values)
            return unless registry_duplicates.any?

            duplicates_info = registry_duplicates.map do |value|
              controls_with_value = find_control_names(controls, [value], :enum_value)
              "#{value}: #{controls_with_value}"
            end.join('; ')

            raise RegistryValidationError, format(DUPLICATE_ENUM_VALUES_ERROR, duplicates_info)
          end

          def find_duplicates(array)
            array.group_by(&:itself).select { |_, items| items.size > 1 }.keys
          end

          def find_control_names(controls, values, key = nil)
            controls
              .filter_map do |id, data|
                check_value = key ? data[key] : data
                id if values.include?(check_value)
              end
              .join(', ')
          end
        end
      end
    end
  end
end
