# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class CustomFields < Grape::Entity
          class SelectOption < Grape::Entity
            expose :id, documentation: { type: 'Integer', example: 1, desc: 'ID of the select option.' } # rubocop:disable API/EntityExposureGrowth -- Pre-existing exposure retained when adding entity to high-impact baseline
            expose :value, documentation: { type: 'String', example: 'High', desc: 'Text of the select option.' } # rubocop:disable API/EntityExposureGrowth -- Pre-existing exposure retained when adding entity to high-impact baseline
          end

          class CustomField < Grape::Entity
            expose :id, documentation: { type: 'Integer', example: 1, desc: 'ID of the custom field.' } # rubocop:disable API/EntityExposureGrowth -- Pre-existing exposure retained when adding entity to high-impact baseline
            expose :name, documentation: { type: 'String', example: 'Priority', desc: 'Name of the custom field.' }
            expose :field_type,
              documentation: {
                type: 'String', example: 'single_select', values: ::Issuables::CustomField.field_types.keys,
                desc: 'Type of the custom field. Select fields return their value in `selected_options`, ' \
                  'other types in `value`.'
              }
            # Work item responses list only active fields (Issuables::CustomFieldsFinder.active_fields_for_work_item).
            expose :active,
              documentation: {
                type: 'Boolean', example: true,
                desc: 'Whether the custom field is active, that is, not archived. ' \
                  'Always `true` in work item responses, which list only active fields.'
              } do |custom_field, _options|
              custom_field.active?
            end
            expose :created_at,
              documentation: {
                type: 'DateTime', example: '2024-02-12T09:45:00Z', desc: 'Time the custom field was created.'
              }
            expose :updated_at,
              documentation: {
                type: 'DateTime', example: '2024-02-12T09:45:00Z', desc: 'Time the custom field was last updated.'
              }
            expose :created_by, using: ::API::Entities::UserBasic,
              documentation: {
                type: 'Entities::UserBasic', desc: 'User who created the custom field. Null if unknown.'
              },
              expose_nil: true
            expose :updated_by, using: ::API::Entities::UserBasic,
              documentation: {
                type: 'Entities::UserBasic',
                desc: 'User who last updated the custom field. Null if it was never updated or the user is unknown.'
              },
              expose_nil: true
            expose :select_options,
              using: ::API::Entities::WorkItems::Features::CustomFields::SelectOption,
              documentation: {
                type: 'Entities::WorkItems::Features::CustomFields::SelectOption', is_array: true,
                desc: 'Options of a select field, in display order. Omitted for other field types.'
              },
              if: ->(custom_field, _) { custom_field.field_type_select? }
            expose :work_item_types,
              using: ::API::Entities::WorkItems::Type,
              documentation: {
                type: 'Entities::WorkItems::Type', is_array: true,
                desc: 'Work item types the custom field is available for, sorted by name.'
              }
          end

          class CustomFieldValue < Grape::Entity
            expose :custom_field,
              using: ::API::Entities::WorkItems::Features::CustomFields::CustomField,
              documentation: {
                type: 'Entities::WorkItems::Features::CustomFields::CustomField', desc: 'Custom field the value is for.'
              }

            expose :value, # rubocop:disable API/EntityExposureGrowth -- Pre-existing exposure retained when adding entity to high-impact baseline
              documentation: {
                type: 'String', example: 'In progress',
                desc: 'Value of a number, text, or date field: a number, a string, or a date in `YYYY-MM-DD` format. ' \
                  'Null if not set. Omitted for select fields.'
              },
              if: ->(field_value, _) { !field_value[:custom_field].field_type_select? } do |field_value|
                value = field_value[:value]
                # Number values are stored as a numeric column (BigDecimal) which would otherwise
                # serialize to a JSON string. Coerce to Float to keep parity with the GraphQL API.
                field_value[:custom_field].field_type_number? && value ? value.to_f : value
              end

            expose :selected_options,
              using: ::API::Entities::WorkItems::Features::CustomFields::SelectOption,
              documentation: {
                type: 'Entities::WorkItems::Features::CustomFields::SelectOption', is_array: true,
                desc: 'Selected options of a `single_select` or `multi_select` field, in display order. ' \
                  'Null if no option is selected. Omitted for other field types.'
              },
              if: ->(field_value, _) { field_value[:custom_field].field_type_select? } do |field_value|
                field_value[:value]
              end
          end

          expose :custom_field_values,
            using: ::API::Entities::WorkItems::Features::CustomFields::CustomFieldValue,
            documentation: {
              type: 'Entities::WorkItems::Features::CustomFields::CustomFieldValue', is_array: true,
              desc: "Active custom fields of the top-level group that are available for the work item's type, " \
                'each with its value on this work item. Includes fields that have no value.'
            },
            expose_nil: true do |feature, _options|
              feature.custom_field_values
            end
        end
      end
    end
  end
end
