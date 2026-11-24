# frozen_string_literal: true

module Issuables
  module CustomFields
    class UnarchiveService < BaseGroupService
      NotAuthorizedError = ServiceResponse.error(
        message: "You don't have permissions to update a custom field for this group."
      )
      AlreadyActiveError = ServiceResponse.error(
        message: 'Custom field is already active.'
      )

      attr_reader :custom_field

      def initialize(custom_field:, **kwargs)
        super(group: custom_field.namespace, **kwargs)

        @custom_field = custom_field
      end

      def execute
        return NotAuthorizedError unless can?(current_user, :admin_custom_field, group)
        return AlreadyActiveError if custom_field.active?

        custom_field.archived_at = nil

        if custom_field.save
          ServiceResponse.success(payload: { custom_field: custom_field })
        else
          ServiceResponse.error(message: custom_field.errors.full_messages)
        end
      end
    end
  end
end
