# frozen_string_literal: true

module EE
  module AuditEvents
    module UserAuditEvent
      include ::Gitlab::Utils::StrongMemoize
      include ::AuditEvents::CommonAuditEventStreamable

      attr_accessor :root_group_entity_id
      attr_writer :entity, :user

      def user
        lazy_user
      end
      strong_memoize_attr :user

      def entity
        user
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
        nil
      end

      private

      def lazy_user
        BatchLoader.for(user_id).batch(default_value: ::Gitlab::Audit::NullEntity.new) do |ids, loader|
          ::User.id_in(ids).find_each { |record| loader.call(record.id, record) }
        end
      end
    end
  end
end
