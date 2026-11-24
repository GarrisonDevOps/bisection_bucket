# frozen_string_literal: true

module EE
  module AuditEvents
    module GroupAuditEvent
      include ::Gitlab::Utils::StrongMemoize
      include ::AuditEvents::CommonAuditEventStreamable

      attr_accessor :root_group_entity_id
      attr_writer :group

      def group
        lazy_group
      end
      strong_memoize_attr :group

      def entity
        group
      end

      def present
        AuditEventPresenter.new(self)
      end

      def root_group_entity
        return ::Group.find_by(id: root_group_entity_id) if root_group_entity_id.present?
        return if group.nil?

        root_group_entity = group.root_ancestor
        self.root_group_entity_id = root_group_entity.id
        root_group_entity
      end
      strong_memoize_attr :root_group_entity

      def streamable_namespace
        group
      end
      strong_memoize_attr :streamable_namespace

      private

      def lazy_group
        BatchLoader.for(group_id).batch(default_value: ::Gitlab::Audit::NullEntity.new) do |ids, loader|
          ::Group.id_in(ids).find_each { |record| loader.call(record.id, record) }
        end
      end
    end
  end
end
