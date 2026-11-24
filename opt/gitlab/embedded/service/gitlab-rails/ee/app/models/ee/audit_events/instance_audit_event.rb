# frozen_string_literal: true

module EE
  module AuditEvents
    module InstanceAuditEvent
      include ::Gitlab::Utils::StrongMemoize
      include ::AuditEvents::CommonAuditEventStreamable

      attr_accessor :root_group_entity_id
      attr_writer :entity

      def entity
        ::Gitlab::Audit::InstanceScope.new
      end
      strong_memoize_attr :entity

      def present
        AuditEventPresenter.new(self)
      end

      def root_group_entity
        nil
      end
      strong_memoize_attr :root_group_entity

      def streamable_namespace
        return unless target_type && target_id

        case target_type
        when 'Project'
          ::Project.find_by(id: target_id)&.then(&:project_namespace)
        when 'Group'
          ::Group.find_by(id: target_id)
        when 'Namespaces::ProjectNamespace'
          ::Namespaces::ProjectNamespace.find_by(id: target_id)
        end
      end
      strong_memoize_attr :streamable_namespace
    end
  end
end
