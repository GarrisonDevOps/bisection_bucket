# frozen_string_literal: true

module AuditEvents
  class ExternalAuditEventDestination < ApplicationRecord
    include CustomHttpExternallyDestinationable
    include Limitable
    include ExternallyCommonDestinationable
    include GroupStreamDestinationMappable
    include Activatable

    self.limit_name = 'external_audit_event_destinations'
    self.limit_scope = :group
    self.table_name = 'audit_events_external_audit_event_destinations'

    belongs_to :group, class_name: '::Group', foreign_key: 'namespace_id',
      inverse_of: :external_audit_event_destinations
    has_many :headers, class_name: 'AuditEvents::Streaming::Header'
    has_many :event_type_filters, class_name: 'AuditEvents::Streaming::EventTypeFilter'

    has_one :namespace_filter, class_name: 'AuditEvents::Streaming::HTTP::NamespaceFilter',
      inverse_of: :external_audit_event_destination

    validate :root_level_group?
    validates :name, uniqueness: { scope: :namespace_id }
    validates :destination_url, uniqueness: { scope: :namespace_id }, length: { maximum: 255 }
    validates :verification_token,
      uniqueness: { scope: :namespace_id },
      allow_nil: true

    def allowed_to_stream?(audit_event_type, audit_event)
      return false unless entity_allowed_to_stream?(audit_event)

      event_type_allowed_to_stream?(audit_event_type)
    end

    private

    def entity_allowed_to_stream?(audit_event)
      if namespace_filter.present?
        audit_event_entity = audit_event.entity

        audit_event_entity = audit_event_entity.project_namespace if audit_event_entity.is_a?(::Project)

        # Return false if namespace(entity) of audit event
        #   - is project or group and
        #   - is self or descendant of the filter namespace
        return false if (audit_event_entity.is_a?(::Namespaces::ProjectNamespace) ||
          audit_event_entity.is_a?(::Group)) &&
          audit_event_entity.self_and_ancestor_ids.exclude?(namespace_filter.namespace.id)
      end

      true
    end

    def root_level_group?
      errors.add(:group, 'must not be a subgroup') if group.subgroup?
    end
  end
end
