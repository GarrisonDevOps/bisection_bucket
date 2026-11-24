# frozen_string_literal: true

module Notifications
  module TargetedMessages
    class CreateService < BaseService
      def execute
        parse_namespaces

        @targeted_message = Notifications::TargetedMessage.new(targeted_message_params)

        success = Notifications::TargetedMessage.transaction do
          raise ActiveRecord::Rollback unless @targeted_message.save

          parsed_namespaces[:valid_namespace_ids][1..].each_slice(1000) do |namespace_ids|
            namespace_data = namespace_ids.map do |namespace_id|
              {
                targeted_message_id: @targeted_message.id,
                namespace_id: namespace_id
              }
            end

            Notifications::TargetedMessageNamespace.insert_all(namespace_data)
          end
        end

        if success
          handle_success
        else
          handle_failure
        end
      end

      private

      def targeted_message_params
        params.merge(namespace_ids: parsed_namespaces[:valid_namespace_ids].first)
      end

      def handle_success
        if partial_success?
          ServiceResponse.error(
            message: format(
              s_('TargetedMessages|Targeted message was successfully created. But %{invalid_namespace_ids_message}'),
              invalid_namespace_ids_message: parsed_namespaces[:message]
            ),
            payload: targeted_message,
            reason: FOUND_INVALID_NAMESPACES
          )
        else
          success
        end
      end
    end
  end
end
