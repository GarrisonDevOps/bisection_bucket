# frozen_string_literal: true

module AuditEvents
  module Group
    class EventTypeFilter < ApplicationRecord
      include AuditEvents::Streaming::StreamableEventTypeFilter

      self.table_name = 'audit_events_group_streaming_event_type_filters'

      belongs_to :external_streaming_destination, class_name: 'ExternalStreamingDestination'
      belongs_to :namespace, class_name: '::Group', default: -> { external_streaming_destination&.group }

      enum :kind, { allow: 0, deny: 1 }, default: :allow

      scope :allowlist, -> { allow }
      scope :denylist, -> { deny }

      validates :namespace, presence: true

      validate :namespace_and_destination_match?

      validates :audit_event_type,
        presence: true,
        length: { maximum: 255 },
        uniqueness: { scope: :external_streaming_destination_id }

      private

      def namespace_and_destination_match?
        return if external_streaming_destination&.group == namespace

        errors.add(:external_streaming_destination, 'must belong to the group.')
      end
    end
  end
end
