# frozen_string_literal: true

module Ai
  module Catalog
    class ItemVersionDependency < ApplicationRecord
      include BulkInsertSafe

      self.table_name = 'ai_catalog_item_version_dependencies'

      belongs_to :ai_catalog_item_version, class_name: 'Ai::Catalog::ItemVersion', optional: false
      belongs_to :dependency, class_name: 'Ai::Catalog::Item', inverse_of: :dependents, optional: false
      belongs_to :dependency_version, class_name: 'Ai::Catalog::ItemVersion'
      belongs_to :organization, class_name: 'Organizations::Organization', optional: false

      validates :dependency_id, uniqueness: { scope: :ai_catalog_item_version_id }
      scope :for_item_version, ->(item_version) { where(ai_catalog_item_version: item_version) }
      scope :with_resolved_dependencies, -> { preload(:dependency_version, dependency: { project: :namespace }) }

      validate :dependency_version_belongs_to_dependency

      private

      def dependency_version_belongs_to_dependency
        return if dependency_version.nil?
        return if dependency_version.ai_catalog_item_id == dependency_id

        errors.add(:dependency_version, s_('AICatalog|must be a version of the dependency item'))
      end
    end
  end
end
