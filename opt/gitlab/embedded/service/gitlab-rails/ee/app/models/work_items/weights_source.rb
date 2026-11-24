# frozen_string_literal: true

module WorkItems
  class WeightsSource < ApplicationRecord
    self.table_name = 'work_item_weights_sources'

    belongs_to :namespace
    belongs_to :work_item

    before_validation :copy_namespace_from_work_item

    validates :namespace, :work_item, presence: true

    def self.upsert_rolled_up_weights_for(work_item)
      return unless work_item.persisted?

      sql = <<~SQL
        INSERT INTO #{table_name}
          (work_item_id, namespace_id, rolled_up_weight, rolled_up_completed_weight, created_at, updated_at)
          SELECT
            work_items.id,
            work_items.namespace_id,
            SUM(
              COALESCE(work_item_weights_sources.rolled_up_weight, child_work_items.weight)
            ),
            SUM(
              CASE
                 WHEN child_work_items.state_id = #{Issuable::STATE_ID_MAP[:closed]}
                 THEN COALESCE(work_item_weights_sources.rolled_up_weight, child_work_items.weight)
                 ELSE COALESCE(work_item_weights_sources.rolled_up_completed_weight, 0)
              END
            ),
            NOW(),
            NOW()
          FROM issues AS work_items
            LEFT JOIN work_item_parent_links ON work_items.id = work_item_parent_links.work_item_parent_id
            LEFT JOIN issues AS child_work_items ON work_item_parent_links.work_item_id = child_work_items.id
            LEFT JOIN work_item_weights_sources ON child_work_items.id = work_item_weights_sources.work_item_id
          WHERE work_items.id = #{work_item.id}
          GROUP BY work_items.id, work_items.namespace_id
        ON CONFLICT (work_item_id)
        DO UPDATE SET
          rolled_up_weight = EXCLUDED.rolled_up_weight,
          rolled_up_completed_weight = EXCLUDED.rolled_up_completed_weight,
          updated_at = NOW()
        RETURNING work_item_id
      SQL

      connection.execute(sql)
    end

    private

    def copy_namespace_from_work_item
      self.namespace = work_item&.namespace
    end
  end
end
