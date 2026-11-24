# frozen_string_literal: true

module AuditEvents
  module Streaming
    module HeadersOperations
      include ::AuditEvents::HeadersSyncHelper

      def create_header(destination, key, value, active)
        header = destination.headers.new(key: key, value: value, active: active)

        if header.save
          audit_message = "Created custom HTTP header with key #{key}."
          audit(action: :create, header: header, message: audit_message)

          sync_header_to_streaming_destination(destination, header)

          ServiceResponse.success(payload: { header: header, errors: [] })
        else
          ServiceResponse.error(message: Array(header.errors))
        end
      end

      def update_header(header, params)
        update_params = params.slice(:key, :value, :active).compact
        old_key = header.key
        destination = header.destination

        if header.update(update_params)
          log_update_audit_event(header)

          sync_header_to_streaming_destination(destination, header, old_key)

          ServiceResponse.success(payload: { header: header, errors: [] })
        else
          ServiceResponse.error(message: Array(header.errors))
        end
      end

      def destroy_header(header)
        destination = header.destination

        if header.destroy
          audit_message = "Destroyed a custom HTTP header with key #{header.key}."
          audit(action: :destroy, header: header, message: audit_message)

          sync_header_deletion_to_streaming_destination(destination, header.key)

          ServiceResponse.success
        else
          ServiceResponse.error(message: Array(header.errors))
        end
      end

      private

      def log_update_audit_event(header)
        changes = header.previous_changes.except(:updated_at)
        return if changes.empty?

        audit(action: :update, header: header, message: update_audit_message(header, changes),
          additional_details: changes)
      end

      def update_audit_message(header, changes)
        message = "Updated a custom HTTP header "

        message += if changes.key?(:key)
                     "from key #{changes[:key].first} to have a key #{changes[:key].last}"
                   else
                     "with key #{header.key}"
                   end

        message += " to have a new value" if changes.key?(:value)
        message += " activation status changed to #{changes[:active].last}" if changes.key?(:active)
        message += "."

        message
      end
    end
  end
end
