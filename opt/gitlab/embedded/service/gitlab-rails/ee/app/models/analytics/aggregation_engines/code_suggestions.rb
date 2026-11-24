# frozen_string_literal: true

module Analytics
  module AggregationEngines
    class CodeSuggestions < Gitlab::Database::Aggregation::ClickHouse::Engine
      self.table_name = 'ai_code_suggestions'

      include Support::BaseAggregationScope

      self.scope_path_column = :namespace_path
      self.scope_path_with_organization = false

      filters do
        exact_match :user_id, :string, description: 'Filter by one or many user Global IDs',
          formatter: gid_formatter
        exact_not_match :user_id, :string,
          description: 'Exclude one or many user Global IDs.',
          formatter: gid_formatter, max_size: MAX_EXCLUSION_VALUES
        exact_match :language, :string, description: 'Filter by suggestion language'
        exact_not_match :language, :string,
          description: 'Exclude one or many suggestion languages.',
          max_size: MAX_EXCLUSION_VALUES
        exact_match :ide_name, :string, description: 'Filter by IDE name'
        exact_not_match :ide_name, :string,
          description: 'Exclude one or many IDE names.',
          max_size: MAX_EXCLUSION_VALUES
        range :timestamp, :datetime, description: 'Filter by suggestion timestamp'
      end

      dimensions do
        column :language, :string, description: 'Programming language'
        column :ide_name, :string, description: 'IDE name'
        column :user_id, :integer, description: 'User', association: true
        date_bucket :timestamp, :date, description: 'Suggestion date'
      end

      metrics do
        count description: 'Total number of suggestions'
        count :users, :integer, -> { sql('user_id') }, distinct: true, description: 'Number of unique users'

        rate :acceptance, numerator_if: ->(_params) {
          sql('maxIfMerge(accepted_at) IS NOT NULL')
        }, denominator_if: ->(_params) {
          sql('minIfMerge(shown_at) IS NOT NULL')
        }, description: 'Acceptance rate (accepted / shown)'

        sum :suggestion_size, :integer, ->(_params) {
          sql('suggestion_size')
        }, description: 'Total suggestions volume'

        count :accepted, if: ->(_params) {
          sql('maxIfMerge(accepted_at) IS NOT NULL')
        }, description: 'Number of accepted suggestions'

        count :rejected, if: ->(_params) {
          sql('maxIfMerge(rejected_at) IS NOT NULL')
        }, description: 'Number of rejected suggestions'

        count :shown, if: ->(_params) {
          sql('minIfMerge(shown_at) IS NOT NULL')
        }, description: 'Number of shown suggestions'
      end
    end
  end
end
