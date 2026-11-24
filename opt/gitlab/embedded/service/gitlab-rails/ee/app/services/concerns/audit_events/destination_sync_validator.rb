# frozen_string_literal: true

module AuditEvents
  module DestinationSyncValidator
    def should_sync_http?(destination)
      is_legacy = destination.respond_to?(:stream_destination_id)

      if is_legacy
        return false unless destination.stream_destination_id.present?

        stream_destination = destination.stream_destination
      else
        return false unless destination.legacy_destination_ref.present?

        stream_destination = destination
      end

      return false unless stream_destination.http?

      true
    end
  end
end
