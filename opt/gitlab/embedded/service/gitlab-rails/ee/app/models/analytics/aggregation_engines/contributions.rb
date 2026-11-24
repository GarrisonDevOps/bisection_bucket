# frozen_string_literal: true

module Analytics
  module AggregationEngines
    class Contributions < Gitlab::Database::Aggregation::ClickHouse::Engine
      self.table_name = 'contributions_new'

      include Support::BaseAggregationScope

      self.scope_path_column = :path

      metrics do
        count :users, :integer, -> { sql('author_id') }, distinct: true, description: 'Number of unique contributors'
        count description: 'Total number of contributions'
      end

      filters do
        exact_match :author_id, :string, description: 'Filter by one or many author Global IDs',
          formatter: gid_formatter
        exact_not_match :author_id, :string,
          description: 'Exclude one or many author Global IDs.',
          formatter: gid_formatter, max_size: MAX_EXCLUSION_VALUES
        range :created_at, :datetime, description: 'Filter by contribution timestamp'
      end

      dimensions do
        column :author_id, :integer, description: 'Contribution author', association: { model: ::User }
        date_bucket :created_at, :date, description: 'Contribution date'
      end
    end
  end
end
