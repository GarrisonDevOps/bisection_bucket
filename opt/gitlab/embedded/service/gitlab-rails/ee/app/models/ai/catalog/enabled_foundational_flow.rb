# frozen_string_literal: true

module Ai
  module Catalog
    class EnabledFoundationalFlow < ApplicationRecord
      self.table_name = 'enabled_foundational_flows'

      belongs_to :namespace, optional: true
      belongs_to :project, optional: true
      belongs_to :catalog_item, class_name: 'Ai::Catalog::Item'

      # BulkInsertSafe must be included after has_many associations are defined to avoid raising an error.
      include BulkInsertSafe

      validates :catalog_item_id, presence: true
      validates :catalog_item_id,
        uniqueness: { scope: :namespace_id },
        if: :namespace_id?
      validates :catalog_item_id,
        uniqueness: { scope: :project_id },
        if: :project_id?
      validate :belongs_to_namespace_or_project
      validate :catalog_item_is_foundational_flow

      scope :for_namespace, ->(namespace_id) { where(namespace_id: namespace_id, project_id: nil) }
      scope :for_project, ->(project_id) { where(project_id: project_id, namespace_id: nil) }
      scope :excluding_catalog_items, ->(catalog_item_ids) { where.not(catalog_item_id: catalog_item_ids) }
      scope :limited_catalog_item_ids, ->(limit = ::Ai::Catalog::Item::FOUNDATIONAL_FLOWS_LIMIT) do
        limit(limit).pluck(:catalog_item_id)
      end

      private

      def belongs_to_namespace_or_project
        return if namespace_id.present? ^ project_id.present?

        errors.add(:base, 'must belong to either namespace or project')
      end

      def catalog_item_is_foundational_flow
        return unless catalog_item_id

        return if ::Ai::Catalog::Item.foundational_flows.exists?(id: catalog_item_id)

        errors.add(:catalog_item_id, 'must be a foundational flow')
      end
    end
  end
end
