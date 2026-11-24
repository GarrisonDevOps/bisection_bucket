# frozen_string_literal: true

module Resolvers
  module WorkItems
    class TypeCustomFieldValuesResolver < BaseResolver
      include LooksAhead
      include ::Issuables::CustomFields::LookAheadPreloads
      extend ::Gitlab::Utils::Override

      type [Types::WorkItems::CustomFieldValueInterface], null: true

      def resolve_with_lookahead
        group = context[:resource_parent].root_ancestor

        BatchLoader::GraphQL.for({ group: group, work_item_type_id: object.work_item_type_id }).batch do |items, loader|
          work_item_type_ids_by_group = index_batch_loader_keys_by_group(items)

          work_item_type_ids_by_group.each do |group, work_item_type_ids|
            custom_fields = ::Issuables::CustomFieldsFinder.new(
              current_user,
              group: group,
              active: true,
              work_item_type_ids: work_item_type_ids
            ).execute

            custom_fields = apply_lookahead(custom_fields)

            custom_fields_by_work_item_type_id = index_results_by_work_item_type_id(custom_fields)

            custom_fields_by_work_item_type_id.each do |work_item_type_id, fields|
              loader.call(
                { group: group, work_item_type_id: work_item_type_id },
                convert_to_empty_field_values(fields)
              )
            end
          end
        end
      end

      private

      def index_batch_loader_keys_by_group(items)
        items.each_with_object({}) do |item, result|
          result[item[:group]] ||= []
          result[item[:group]] << item[:work_item_type_id]
        end
      end

      def index_results_by_work_item_type_id(custom_fields)
        custom_fields.each_with_object({}) do |custom_field, result|
          custom_field.work_item_type_ids.each do |work_item_type_id|
            result[work_item_type_id] ||= []
            result[work_item_type_id] << custom_field
          end
        end
      end

      def convert_to_empty_field_values(custom_fields)
        custom_fields.map do |field|
          {
            custom_field: field,
            value: nil
          }
        end
      end

      override :unconditional_includes
      def unconditional_includes
        super + [:work_item_type_custom_fields]
      end

      def preloads
        custom_field_preloads.transform_keys do |field|
          [:custom_field, field]
        end
      end
    end
  end
end
