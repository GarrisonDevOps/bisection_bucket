# frozen_string_literal: true

module Ai
  module TokenDailyUsages
    class FlushBufferService
      BATCH_SIZE = 1000
      DAY_KEY = %w[organization_id traversal_ids user_id feature model usage_date].freeze
      UPSERT_OPTIONS = {
        unique_by: DAY_KEY.map(&:to_sym),
        on_duplicate: Arel.sql(<<~SQL.squish)
          input_tokens = ai_token_daily_usages.input_tokens + excluded.input_tokens,
          output_tokens = ai_token_daily_usages.output_tokens + excluded.output_tokens,
          events_count = ai_token_daily_usages.events_count + excluded.events_count,
          updated_at = excluded.updated_at
        SQL
      }.freeze

      def execute
        batch = ::Ai::TokenDailyUsage.write_buffer.pop(BATCH_SIZE)
        usages = unique_usages(batch)
        valid_usages = usages.select(&:valid?)
        dropped_rows = usages.size - valid_usages.size
        rows = daily_rows(valid_usages)
        return ServiceResponse.success(payload: { inserted_rows: 0, dropped_rows: dropped_rows }) if rows.empty?

        result = ::Ai::TokenDailyUsage.upsert_all(rows, **UPSERT_OPTIONS)
        ServiceResponse.success(payload: { inserted_rows: result.rows.size, dropped_rows: dropped_rows })
      rescue StandardError
        ::Ai::TokenDailyUsage.write_buffer.requeue(batch) if batch.present?
        raise
      end

      private

      def unique_usages(batch)
        usages = batch.uniq { |row| row.values_at('namespace_id', 'user_id', 'event', 'timestamp', 'model') }
          .map { |row| ::Ai::TokenDailyUsage.new(row.slice(*::Ai::TokenDailyUsage.attribute_names)) }

        use_current_organizations(usages)
        usages
      end

      # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- one lookup per batch of at most BATCH_SIZE rows
      def use_current_organizations(usages)
        in_namespace, without_namespace = usages.partition { |usage| usage.traversal_ids.present? }
        namespace_organizations = organizations_of(::Namespace, in_namespace.map { |usage| usage.traversal_ids.last })
        user_organizations = organizations_of(::User, without_namespace.map(&:user_id))

        in_namespace.each do |usage|
          usage.organization_id = namespace_organizations.fetch(usage.traversal_ids.last, usage.organization_id)
        end

        without_namespace.each do |usage|
          usage.organization_id = user_organizations.fetch(usage.user_id, usage.organization_id)
        end
      end

      def organizations_of(model, ids)
        model.id_in(ids.uniq).pluck(:id, :organization_id).to_h
      end
      # rubocop:enable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit

      def daily_rows(usages)
        usages.group_by { |usage| usage.attributes.slice(*DAY_KEY) }.map do |day_key, day_usages|
          day_key.merge(
            'input_tokens' => day_usages.sum(&:input_tokens),
            'output_tokens' => day_usages.sum(&:output_tokens),
            'events_count' => day_usages.sum(&:events_count)
          )
        end
      end
    end
  end
end
