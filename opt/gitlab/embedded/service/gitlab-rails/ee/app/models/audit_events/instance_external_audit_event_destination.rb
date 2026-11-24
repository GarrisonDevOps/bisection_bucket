# frozen_string_literal: true

module AuditEvents
  class InstanceExternalAuditEventDestination < ApplicationRecord
    include ExternallyCommonDestinationable
    include CustomHttpExternallyDestinationable
    include Limitable
    include InstanceStreamDestinationMappable
    include Gitlab::EncryptedAttribute
    include Activatable

    self.limit_name = 'external_audit_event_destinations'
    self.limit_scope = Limitable::GLOBAL_SCOPE
    self.table_name = 'audit_events_instance_external_audit_event_destinations'

    has_many :headers, class_name: 'AuditEvents::Streaming::InstanceHeader'
    has_many :event_type_filters, class_name: 'AuditEvents::Streaming::InstanceEventTypeFilter'

    has_one :namespace_filter,
      class_name: 'AuditEvents::Streaming::HTTP::Instance::NamespaceFilter',
      foreign_key: 'audit_events_instance_external_audit_event_destination_id',
      inverse_of: :instance_external_audit_event_destination

    validates :name, uniqueness: true
    validates :destination_url, uniqueness: true, length: { maximum: 255 }

    attr_encrypted :verification_token,
      mode: :per_attribute_iv,
      algorithm: 'aes-256-gcm',
      key: :db_key_base_32,
      encode: false,
      encode_iv: false

    def allowed_to_stream?(audit_event_type, _audit_event)
      event_type_allowed_to_stream?(audit_event_type)
    end
  end
end
