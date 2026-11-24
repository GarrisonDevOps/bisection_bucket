# frozen_string_literal: true

module Issuables
  module CustomFields
    class CreateService < BaseGroupService
      include Gitlab::InternalEventsTracking

      NotAuthorizedError = ServiceResponse.error(
        message: "You don't have permissions to create a custom field for this group."
      )

      def execute
        return NotAuthorizedError unless can?(current_user, :admin_custom_field, group)

        custom_field = Issuables::CustomField.new(
          namespace: group,
          created_by: current_user
        )

        custom_field.assign_attributes(params.slice(:field_type, :name, :work_item_type_ids))
        handle_select_options(custom_field)

        if custom_field.save
          custom_field.reset_ordered_associations

          track_internal_event(
            'create_custom_field_in_group_settings',
            namespace: group,
            user: current_user,
            additional_properties: {
              label: custom_field.field_type,
              property: custom_field.work_item_type_ids.sort.join(','),
              field_name: custom_field.name
            }
          )

          ServiceResponse.success(payload: { custom_field: custom_field })
        else
          ServiceResponse.error(message: custom_field.errors.full_messages)
        end
      end

      private

      def handle_select_options(custom_field)
        return unless params[:select_options]

        params[:select_options].each_with_index do |option, i|
          custom_field.select_options.build(value: option[:value], position: i)
        end
      end
    end
  end
end
