# frozen_string_literal: true

module AuditEvents
  module Instance
    class ExternalStreamingDestination < ApplicationRecord
      include Limitable
      include ExternallyStreamable
      include LegacyDestinationMappable
      include Activatable

      self.limit_name = 'external_audit_event_destinations'
      self.limit_scope = Limitable::GLOBAL_SCOPE
      self.table_name = 'audit_events_instance_external_streaming_destinations'

      validates :name, uniqueness: { scope: [:category] }

      has_many :event_type_filters, -> { allowlist }, class_name: 'AuditEvents::Instance::EventTypeFilter',
        inverse_of: :external_streaming_destination
      has_many :event_type_denylist_filters, -> { denylist }, class_name: 'AuditEvents::Instance::EventTypeFilter',
        inverse_of: :external_streaming_destination
      has_many :namespace_filters, class_name: 'AuditEvents::Instance::NamespaceFilter'

      # Lets the batched consumer evaluate allowed_to_stream? filters from
      # memory instead of a query per destination per batch.
      scope :preload_filters, -> {
        preload(:event_type_filters, :event_type_denylist_filters, namespace_filters: :namespace)
      }
    end
  end
end
