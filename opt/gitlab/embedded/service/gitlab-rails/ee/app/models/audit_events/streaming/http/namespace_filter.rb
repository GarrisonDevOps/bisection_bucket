# frozen_string_literal: true

module AuditEvents
  module Streaming
    module HTTP
      class NamespaceFilter < ApplicationRecord
        include NamespaceFilterable

        self.table_name = 'audit_events_streaming_http_group_namespace_filters'

        belongs_to :external_audit_event_destination, inverse_of: :namespace_filter
        belongs_to :namespace, inverse_of: :audit_event_http_namespace_filter

        has_one :group, through: :external_audit_event_destination

        validates :external_audit_event_destination, presence: true, uniqueness: true
        validates :namespace, presence: true, uniqueness: true

        validate :valid_destination_for_namespace,
          if: -> { namespace.present? && external_audit_event_destination.present? }

        private

        def valid_destination_for_namespace
          return if namespace.root_ancestor == external_audit_event_destination.group

          errors.add(:external_audit_event_destination, 'does not belong to the top-level group of the namespace.')
        end
      end
    end
  end
end
