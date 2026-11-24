# frozen_string_literal: true

module AuditEvents
  module Instance
    class NamespaceFilter < ApplicationRecord
      include AuditEvents::Streaming::HTTP::NamespaceFilterable
      include AuditEvents::NamespaceFilterLimitable

      self.table_name = 'audit_events_streaming_instance_namespace_filters'

      belongs_to :namespace, inverse_of: :audit_events_streaming_instance_namespace_filters
      belongs_to :external_streaming_destination,
        class_name: 'ExternalStreamingDestination', inverse_of: :namespace_filters

      validates :namespace, presence: true, uniqueness: { scope: :external_streaming_destination_id }
      validates :external_streaming_destination, presence: true
    end
  end
end
