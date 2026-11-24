# frozen_string_literal: true

module AuditEvents
  module Streaming
    module HTTP
      module Instance
        class NamespaceFilter < ApplicationRecord
          include NamespaceFilterable

          self.table_name = 'audit_events_streaming_http_instance_namespace_filters'

          belongs_to :instance_external_audit_event_destination,
            class_name: '::AuditEvents::InstanceExternalAuditEventDestination',
            foreign_key: 'audit_events_instance_external_audit_event_destination_id',
            inverse_of: :namespace_filter
          belongs_to :namespace, inverse_of: :audit_event_http_instance_namespace_filter

          validates :namespace, presence: true
          validates :instance_external_audit_event_destination, presence: true, uniqueness: true
        end
      end
    end
  end
end
