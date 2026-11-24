# frozen_string_literal: true

module AuditEvents
  module Group
    class NamespaceFilter < ApplicationRecord
      include AuditEvents::Streaming::HTTP::NamespaceFilterable
      include AuditEvents::NamespaceFilterLimitable

      self.table_name = 'audit_events_streaming_group_namespace_filters'

      belongs_to :namespace, inverse_of: :audit_events_streaming_group_namespace_filters
      belongs_to :external_streaming_destination, class_name: 'ExternalStreamingDestination',
        inverse_of: :namespace_filters

      has_one :group, through: :external_streaming_destination

      validates :namespace, presence: true, uniqueness: { scope: :external_streaming_destination_id }
      validates :external_streaming_destination, presence: true

      validate :valid_destination_for_namespace,
        if: -> { namespace.present? && external_streaming_destination.present? }

      private

      def valid_destination_for_namespace
        return if namespace.root_ancestor == external_streaming_destination.group

        errors.add(:external_streaming_destination, _('does not belong to the top-level group of the namespace.'))
      end
    end
  end
end
