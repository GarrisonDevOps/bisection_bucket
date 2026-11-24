# frozen_string_literal: true

module WorkItems
  module Callbacks
    class CustomFields < Base
      include Gitlab::InternalEventsTracking

      # `params` for this widget callback is normally an Array of hashes:
      # [
      #   { custom_field_id: 1, text_value: 'text' },
      #   { custom_field_id: 2, number_value: 100 },
      #   { custom_field_id: 3, selected_option_ids: [1, 2, 3] }
      # ]
      # Only values for the provided custom_field_ids are mutated. Omitted ones are left as-is.
      #
      # During a work item type conversion where the target type does not include the
      # custom_fields widget, WidgetableService sets params to { excluded_in_new_type: true }
      # instead. In that case we clear all existing custom field values for the work item.
      def after_save
        if params.is_a?(Hash) && excluded_in_new_type?
          clear_all_custom_field_values
          return
        end

        return unless has_permission?(:set_work_item_metadata)

        custom_fields = ::Issuables::CustomFieldsFinder.active_fields_for_work_item(work_item)
                          .id_in(params.pluck(:custom_field_id)) # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- params is an Array
                          .index_by(&:id)

        params.each do |field_params|
          custom_field = custom_fields[field_params[:custom_field_id].to_i]

          raise_error "Invalid custom field ID: #{field_params[:custom_field_id]}" if custom_field.nil?

          update_work_item_field_value(custom_field, field_params)
        end

        track_internal_event(
          'change_work_item_custom_field_value',
          namespace: work_item.project&.namespace || work_item.namespace,
          project: work_item.project,
          user: current_user
        )
      end

      private

      def clear_all_custom_field_values
        ::Issuables::CustomField::FIELD_VALUE_CLASSES.each do |klass|
          klass.for_work_item(work_item.id).delete_all
        end
      end

      def update_work_item_field_value(custom_field, field_params)
        if custom_field.field_type_text?
          update_text_field_value(custom_field, field_params[:text_value])
        elsif custom_field.field_type_number?
          update_number_field_value(custom_field, field_params[:number_value])
        elsif custom_field.field_type_date?
          update_date_field_value(custom_field, field_params[:date_value])
        elsif custom_field.field_type_select?
          update_select_field_value(custom_field, Array(field_params[:selected_option_ids]).map(&:to_i))
        else
          raise_error "Unsupported field type: #{custom_field.field_type}"
        end
      rescue ActiveRecord::RecordInvalid, ArgumentError => e
        raise_error e.message
      end

      def update_text_field_value(custom_field, text_value)
        previous_value = ::WorkItems::TextFieldValue.for_field_and_work_item(custom_field.id,
          work_item.id)&.first&.value

        return if text_value == previous_value

        ::WorkItems::TextFieldValue.update_work_item_field!(work_item, custom_field, text_value)

        create_text_field_system_note(custom_field, text_value, previous_value)
      end

      def update_number_field_value(custom_field, number_value)
        previous_value = ::WorkItems::NumberFieldValue.for_field_and_work_item(custom_field.id,
          work_item.id)&.first&.value

        # use `.to_d` method as we store the value as decimal in the DB and number_value is coming from the params
        #  and can be a string
        return if number_value&.to_d == previous_value

        ::WorkItems::NumberFieldValue.update_work_item_field!(work_item, custom_field, number_value)

        create_number_field_system_note(custom_field, number_value, previous_value)
      end

      def update_date_field_value(custom_field, date_value)
        previous_value = ::WorkItems::DateFieldValue.for_field_and_work_item(custom_field.id,
          work_item.id)&.first&.value

        return if date_value == previous_value

        ::WorkItems::DateFieldValue.update_work_item_field!(work_item, custom_field, date_value)

        create_date_field_system_note(custom_field, date_value, previous_value)
      end

      def update_select_field_value(custom_field, selected_option_ids)
        previous_value_ids = ::WorkItems::SelectFieldValue.for_field_and_work_item(custom_field.id,
          work_item.id).pluck(:custom_field_select_option_id) # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- we limit the number of options

        return if selected_option_ids.sort == previous_value_ids.sort

        select_options = custom_field.select_options.id_in(previous_value_ids + selected_option_ids)

        previous_values = select_options.filter_map do |option|
          option.value if previous_value_ids.include?(option.id)
        end

        ::WorkItems::SelectFieldValue.update_work_item_field!(work_item, custom_field, selected_option_ids)

        new_values = select_options.filter_map { |option| option.value if selected_option_ids.include?(option.id) }

        create_select_field_system_note(custom_field, new_values, previous_values)
      end

      def create_text_field_system_note(custom_field, value, previous_value)
        issuables_service.change_custom_field_text_type_note(custom_field, previous_value: previous_value,
          value: value)
      end

      def create_number_field_system_note(custom_field, value, previous_value)
        issuables_service.change_custom_field_number_type_note(custom_field, previous_value: previous_value,
          value: value)
      end

      def create_date_field_system_note(custom_field, value, previous_value)
        issuables_service.change_custom_field_date_type_note(custom_field, previous_value: previous_value,
          value: value)
      end

      def create_select_field_system_note(custom_field, new_options, previous_options)
        issuables_service.change_custom_field_select_type_note(custom_field, new_options: new_options,
          previous_options: previous_options)
      end

      def issuables_service
        ::SystemNotes::IssuablesService.new(noteable: work_item, container: work_item.namespace, author: current_user)
      end
    end
  end
end
