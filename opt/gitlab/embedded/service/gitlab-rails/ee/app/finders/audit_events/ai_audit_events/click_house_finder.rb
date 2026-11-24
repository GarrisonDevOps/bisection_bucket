# frozen_string_literal: true

module AuditEvents
  module AiAuditEvents
    class ClickHouseFinder
      # rubocop:disable CodeReuse/ActiveRecord -- Not ActiveRecord but a ClickHouse query builder
      TABLE_NAME = 'ai_audit_events'
      COLUMNS = %i[
        id workflow_id ai_governance_session_id created_at traversal_path event_name author_id ip_address details
      ].freeze

      # `ai_audit_events` uses ReplacingMergeTree with no explicit version column.
      # Deduplication uses GROUP BY on the ORDER BY columns (traversal_path, workflow_id,
      # created_at, id) with `any()` for remaining columns since duplicates are identical.
      GROUP_BY_COLUMNS = %i[traversal_path workflow_id created_at id].freeze

      def self.counts_for_workflows(workflow_ids, min_created_at: nil)
        counts_by(:workflow_id, workflow_ids, min_created_at: min_created_at)
      end

      def self.counts_for_sessions(ai_governance_session_ids, min_created_at: nil)
        counts_by(:ai_governance_session_id, ai_governance_session_ids, min_created_at: min_created_at)
      end

      def self.counts_by(column, ids, min_created_at:)
        return {} if ids.blank?

        # Deduplicate first, then count per `column`.
        # Inner query deduplicates by primary key columns. Duplicates are identical,
        # so also grouping by `column` keeps one row per event.
        inner_builder = ClickHouse::Client::QueryBuilder.new(TABLE_NAME)
          .select(Arel.sql(column.to_s))
          .where(column => ids)
          .group(*(GROUP_BY_COLUMNS | [column]))

        if min_created_at.present?
          # Audit events can't predate their workflow or session, so the earliest
          # start time in the batch is a safe lower bound. The
          # `ai_audit_events` table is partitioned by `created_at`, so this
          # bound lets ClickHouse prune partitions rather than fanning out.
          inner_builder = inner_builder.where(
            Arel::Table.new(TABLE_NAME)[:created_at].gteq(
              min_created_at.utc.strftime('%Y-%m-%d %H:%M:%S')
            )
          )
        end

        query = ClickHouse::Client::QueryBuilder
          .new(TABLE_NAME)
          .select(Arel.sql(column.to_s), Arel.sql('count() AS count'))
          .from(inner_builder, TABLE_NAME)
          .group(column)

        ::ClickHouse::Client.select(query, :main)
          .each_with_object({}) { |row, hash| hash[row[column.to_s]] = row['count'] }
      end
      private_class_method :counts_by

      # Looks up events by exactly one of workflow or ai_governance_session_id.
      #
      # @param created_after [Time, nil] lower bound on created_at, used for partition pruning
      def initialize(workflow: nil, ai_governance_session_id: nil, created_after: nil)
        unless workflow.nil? ^ ai_governance_session_id.nil?
          raise ArgumentError, 'Provide exactly one of workflow or ai_governance_session_id'
        end

        @filter = workflow ? { workflow_id: workflow.id } : { ai_governance_session_id: ai_governance_session_id }
        @created_after = created_after
      end

      def execute
        inner_builder = ClickHouse::Client::QueryBuilder.new(TABLE_NAME)

        inner_projections = COLUMNS.map do |column|
          if GROUP_BY_COLUMNS.include?(column)
            Arel.sql(column.to_s)
          else
            Arel::Nodes::NamedFunction.new('any', [
              Arel::Table.new(TABLE_NAME)[column]
            ]).as(column.to_s)
          end
        end

        inner_query = inner_builder
          .select(*inner_projections)
          .where(@filter)
          .group(*GROUP_BY_COLUMNS)

        if @created_after
          inner_query = inner_query.where(
            Arel::Table.new(TABLE_NAME)[:created_at].gteq(@created_after.utc.strftime('%Y-%m-%d %H:%M:%S'))
          )
        end

        ClickHouse::Client::QueryBuilder
          .new(TABLE_NAME)
          .select(*COLUMNS)
          .from(inner_query, TABLE_NAME)
          .order(:created_at, :desc)
          .order(:id, :desc)
      end
      # rubocop:enable CodeReuse/ActiveRecord
    end
  end
end
