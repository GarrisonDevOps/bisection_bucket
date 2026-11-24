# frozen_string_literal: true

module Issuables
  module CustomFields
    class UpdateService < BaseGroupService
      include Gitlab::InternalEventsTracking

      InvalidSelectOptionId = Class.new(StandardError)

      NotAuthorizedError = ServiceResponse.error(
        message: "You don't have permissions to update a custom field for this group."
      )

      attr_reader :custom_field

      def initialize(custom_field:, **kwargs)
        super(group: custom_field.namespace, **kwargs)

        @custom_field = custom_field
      end

      def execute
        return NotAuthorizedError unless can?(current_user, :admin_custom_field, group)

        store_old_associations!

        custom_field.assign_attributes(params.slice(:name))

        custom_field_saved = custom_field.with_transaction_returning_status do
          handle_select_options
          custom_field.work_item_type_ids = params[:work_item_type_ids] if params[:work_item_type_ids]

          custom_field.updated_by = current_user if has_changes?
          custom_field.save
        end

        if custom_field_saved
          custom_field.reset_ordered_associations

          track_update_event if has_changes?

          ServiceResponse.success(payload: { custom_field: custom_field })
        else
          ServiceResponse.error(message: custom_field.errors.full_messages)
        end
      rescue InvalidSelectOptionId => e
        ServiceResponse.error(message: e.message)
      end

      private

      def handle_select_options
        return if params[:select_options].nil?

        existing_options_by_id = custom_field.select_options.index_by(&:id)

        custom_field.select_options = params[:select_options].map.with_index do |option, i|
          current_option = if option[:id].nil?
                             custom_field.select_options.build
                           else
                             existing_options_by_id[option[:id].to_i]
                           end

          raise InvalidSelectOptionId, "Select option ID #{option[:id]} is invalid." if current_option.nil?

          current_option.assign_attributes(value: option[:value], position: i)
          current_option
        end
      end

      def store_old_associations!
        @old_select_options = custom_field.select_options.to_a
        @old_work_item_type_ids = custom_field.work_item_type_ids.to_a
      end

      def has_changes?
        custom_field.changed? ||
          @old_work_item_type_ids.sort != custom_field.work_item_type_ids.sort ||
          @old_select_options != custom_field.select_options ||
          custom_field.select_options.any?(&:changed?)
      end

      def track_update_event
        track_internal_event('update_custom_field_in_group_settings',
          namespace: group,
          user: current_user,
          additional_properties: {
            label: custom_field.field_type,
            property: custom_field.work_item_type_ids.sort.join(','),
            field_name: custom_field.name
          }
        )
      end
    end
  end
end
