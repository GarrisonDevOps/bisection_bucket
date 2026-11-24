# frozen_string_literal: true

module Notifications
  module TargetedMessages
    class UpdateService < BaseService
      def initialize(targeted_message, params)
        super(params)

        @targeted_message = targeted_message
      end

      def execute
        csv_provided = params.key?(:namespace_ids_csv)
        if csv_provided
          execute_with_namespace_update
        else
          execute_without_namespace_update
        end
      end

      private

      def handle_success
        if partial_success?
          ServiceResponse.error(
            message: format(
              s_('TargetedMessages|Targeted message was successfully updated. But %{invalid_namespace_ids_message}'),
              invalid_namespace_ids_message: parsed_namespaces[:message]
            ),
            payload: targeted_message,
            reason: FOUND_INVALID_NAMESPACES
          )
        else
          success
        end
      end

      def execute_with_namespace_update
        parse_namespaces

        begin
          Notifications::TargetedMessage.transaction do
            @targeted_message.assign_attributes(params)
            @targeted_message.validate!

            update_namespaces

            @targeted_message.association(:targeted_message_namespaces).reset
            @targeted_message.save!
          end

          handle_success
        rescue ActiveRecord::RecordInvalid
          handle_failure
        end
      end

      def execute_without_namespace_update
        @targeted_message.assign_attributes(params)

        if @targeted_message.save
          success
        else
          failure
        end
      end

      def update_namespaces
        existing_namespace_ids = @targeted_message.namespace_ids
        namespaces_to_delete = existing_namespace_ids - parsed_namespaces[:valid_namespace_ids]
        namespaces_to_create = parsed_namespaces[:valid_namespace_ids] - existing_namespace_ids

        @targeted_message.targeted_message_namespaces.for_namespaces(namespaces_to_delete).delete_all

        namespaces_to_create.each_slice(1000) do |namespace_ids|
          namespace_data = namespace_ids.map do |namespace_id|
            {
              targeted_message_id: @targeted_message.id,
              namespace_id: namespace_id
            }
          end

          Notifications::TargetedMessageNamespace.insert_all(namespace_data)
        end
      end
    end
  end
end
