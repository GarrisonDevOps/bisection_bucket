# frozen_string_literal: true

module WorkItems
  module TypesFramework
    class VisibilityDefault < ApplicationRecord
      include WorkItems::TypesFramework::HasType

      self.table_name = 'work_item_type_visibility_defaults'

      belongs_to :organization, class_name: 'Organizations::Organization', optional: true
      belongs_to :namespace, optional: true

      scope :for_settings, ->(settings) {
        if settings.namespace_id
          where(namespace_id: settings.namespace_id)
        else
          where(organization_id: settings.organization_id)
        end
      }

      validates :work_item_type_id, presence: true
      validates :work_item_type_id, uniqueness: { scope: :namespace_id }, if: -> { namespace_id.present? }
      validates :work_item_type_id, uniqueness: { scope: :organization_id }, if: -> { organization_id.present? }
      validates :enabled, inclusion: { in: [true, false] }
      validates_with ExactlyOnePresentValidator, fields: :sharding_keys

      def self.defaults_for_settings(settings)
        for_settings(settings).each_with_object({}) do |row, map|
          map[row.work_item_type_id] = row.enabled
        end
      end

      def self.upsert_for_settings(settings, work_item_type_id:, enabled:)
        for_settings(settings)
          .find_or_initialize_by(work_item_type_id: work_item_type_id)
          .update!(enabled: enabled)
      rescue ActiveRecord::RecordNotUnique
        retry
      end

      private

      # Override HasType#work_items_types_provider to support org-scoped records
      # where namespace is nil. Falls back to organization so the Provider can
      # resolve custom work item types created at the organization level.
      def work_items_types_provider
        ::WorkItems::TypesFramework::Provider.new(namespace || organization)
      end

      def sharding_keys
        [:namespace_id, :organization_id]
      end
    end
  end
end
