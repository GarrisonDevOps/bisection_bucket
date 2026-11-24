# frozen_string_literal: true

module Ai
  module Catalog
    class ItemStar < ApplicationRecord
      self.table_name = "ai_catalog_item_stars"

      belongs_to :item, class_name: 'Ai::Catalog::Item',
        foreign_key: :ai_catalog_item_id, inverse_of: :stars, optional: false
      belongs_to :organization, class_name: 'Organizations::Organization', optional: false
      belongs_to :user, optional: false

      populate_sharding_key :organization_id, source: :item

      validate :organization_matches_item

      after_create :increment_item_star_count
      after_destroy :decrement_item_star_count

      def self.starred_item_ids_for_user(user_id, item_ids)
        where(user_id: user_id, ai_catalog_item_id: item_ids).limit(item_ids.size).pluck(:ai_catalog_item_id).to_set
      end

      private

      def increment_item_star_count
        Ai::Catalog::Item.update_counters(ai_catalog_item_id, star_count: 1)
      end

      def decrement_item_star_count
        Ai::Catalog::Item.update_counters(ai_catalog_item_id, star_count: -1)
      end

      def organization_matches_item
        return unless item && organization_id

        errors.add(:organization_id, :invalid) unless organization_id == item.organization_id
      end
    end
  end
end
