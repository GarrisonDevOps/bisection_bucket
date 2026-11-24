# frozen_string_literal: true

module Ai
  module Catalog
    module Items
      # rubocop: disable CodeReuse/ActiveRecord -- Custom queries required
      class AggregateLast30DayUsageService
        def execute
          update_item_usage_counts

          ServiceResponse.success(message: 'Usage counts updated for AI catalog items')
        end

        private

        def update_item_usage_counts
          Ai::Catalog::Item.not_deleted.select(:id).find_in_batches(batch_size: 1000) do |items|
            item_ids = items.map(&:id)

            usage_counts = Ai::DuoWorkflows::Workflow
              .where(created_at: 30.days.ago..)
              .where.not(ai_catalog_item_version_id: nil)
              .where.not(project_id: nil)
              .joins(:ai_catalog_item_version)
              .where(ai_catalog_item_versions: { ai_catalog_item_id: item_ids })
              .group('ai_catalog_item_versions.ai_catalog_item_id')
              # rubocop:disable Layout/LineLength -- unavoidable
              .select('ai_catalog_item_versions.ai_catalog_item_id, COUNT(DISTINCT duo_workflows_workflows.project_id) as usage_count')
              # rubocop:enable Layout/LineLength -- unavoidable
              .index_by(&:ai_catalog_item_id)

            updates = item_ids.map do |item_id|
              count = usage_counts[item_id]&.usage_count || 0
              [item_id, count]
            end

            bulk_update(
              model: Ai::Catalog::Item,
              table_name: 'ai_catalog_items',
              id_column: 'id',
              update_column: 'last_30_day_usage_count',
              timestamp_column: 'last_30_day_usage_count_updated_at',
              updates: updates
            )
          end
        end

        def bulk_update(model:, table_name:, id_column:, update_column:, timestamp_column:, updates:)
          return if updates.empty?

          connection = model.connection

          case_statement = updates.map do |id, count|
            "WHEN #{connection.quote(id)} THEN #{connection.quote(count)}"
          end.join(' ')

          ids_list = updates.map { |id, _| connection.quote(id) }.join(',')

          connection.execute(<<~SQL.squish)
            UPDATE #{model.adapter_class.quote_table_name(table_name)}
            SET
              #{model.adapter_class.quote_column_name(update_column)} = CASE #{model.adapter_class.quote_column_name(id_column)} #{case_statement} END,
              #{model.adapter_class.quote_column_name(timestamp_column)} = NOW()
            WHERE #{model.adapter_class.quote_column_name(id_column)} IN (#{ids_list})
          SQL
        end
      end
      # rubocop: enable CodeReuse/ActiveRecord
    end
  end
end
