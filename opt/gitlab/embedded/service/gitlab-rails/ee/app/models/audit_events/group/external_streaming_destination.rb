# frozen_string_literal: true

module AuditEvents
  module Group
    class ExternalStreamingDestination < ApplicationRecord
      include Limitable
      include ExternallyStreamable
      include LegacyDestinationMappable
      include Activatable

      self.limit_name = 'external_audit_event_destinations'
      self.limit_scope = :group
      self.table_name = 'audit_events_group_external_streaming_destinations'

      belongs_to :group, class_name: '::Group', inverse_of: :external_audit_event_streaming_destinations
      validate :top_level_group?
      validates :name, uniqueness: { scope: [:category, :group_id] }

      has_many :event_type_filters, -> { allowlist }, class_name: 'AuditEvents::Group::EventTypeFilter',
        inverse_of: :external_streaming_destination
      has_many :event_type_denylist_filters, -> { denylist }, class_name: 'AuditEvents::Group::EventTypeFilter',
        inverse_of: :external_streaming_destination
      has_many :namespace_filters, class_name: 'AuditEvents::Group::NamespaceFilter'

      # Lets the batched consumer evaluate allowed_to_stream? filters from
      # memory instead of a query per destination per batch.
      scope :preload_filters, -> {
        preload(:event_type_filters, :event_type_denylist_filters, namespace_filters: :namespace)
      }

      private

      def top_level_group?
        errors.add(:group, 'must not be a subgroup. Use a top-level group.') if group.subgroup?
      end
    end
  end
end
