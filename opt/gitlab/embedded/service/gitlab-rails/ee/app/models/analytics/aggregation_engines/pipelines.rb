# frozen_string_literal: true

module Analytics
  module AggregationEngines
    class Pipelines < Gitlab::Database::Aggregation::ClickHouse::Engine
      self.table_name = 'siphon_p_ci_pipelines'

      include Support::BaseAggregationScope

      SOURCES = ::Enums::Ci::Pipeline.sources.freeze
      # `unknown` is stored as NULL, which neither IN nor NOT IN can match.
      FILTERABLE_SOURCES = SOURCES.compact.keys.map(&:to_s).freeze
      STATUSES = ::Ci::HasStatus::AVAILABLE_STATUSES.freeze
      COMPLETED_STATUSES = ::Ci::HasStatus::COMPLETED_STATUSES.freeze

      dimensions do
        column :status, :string, description: 'Pipeline status'
        column :source, :string, description: 'Pipeline source',
          formatter: ->(value) { SOURCES.key(value)&.to_s }
        column :ref, :string, description: 'Pipeline ref'
        column :project_id, :integer, description: 'Project', association: {
          finder: ->(ids) { Project.where(id: ids).index_by(&:id) }
        }
        # Pipelines started by a schedule, a trigger token, or an integration have no user.
        column :user_id, :integer, description: 'User who triggered the pipeline', association: true
        date_bucket :started_at, :date, description: 'Pipeline start date'
        date_bucket :finished_at, :date, description: 'Pipeline finish date'
      end

      metrics do
        count description: 'Total number of pipelines, optionally filtered by source or status',
          parameters: {
            source: { type: :string, in: FILTERABLE_SOURCES, array: true,
                      description: 'Only count pipelines with the given sources.',
                      formatter: ->(values) { values.filter_map { |source| SOURCES[source.to_sym] } } },
            status: { type: :string, in: STATUSES, array: true,
                      description: 'Only count pipelines with the given statuses.' }
          }

        # DEPRECATED: use the `duration` measurement instead
        quantile :duration, :float, ->(_params) {
          sql('duration')
        }, description: 'Pipeline duration quantile in seconds', parameters: {
          quantile: { type: :float, in: 0.0..1.0 }
        }

        rate :outcome,
          numerator_if: ->(params) {
            statuses = Array.wrap(params[:status]) & COMPLETED_STATUSES
            return sql('FALSE') if statuses.empty?

            sql("status IN (#{statuses.map { |s| "'#{s}'" }.join(', ')})")
          },
          denominator_if: ->(_params) { sql("status IN (#{COMPLETED_STATUSES.map { |s| "'#{s}'" }.join(', ')})") },
          description: 'Rate of pipelines with the given status among completed pipelines',
          parameters: {
            status: { type: :string, in: COMPLETED_STATUSES, array: true }
          }
      end

      measurement :duration, :integer, ->(_params) { sql('duration') },
        description: 'Pipeline duration in seconds'

      filters do
        exact_match :status, :string, description: 'Filter by one or many pipeline statuses'
        exact_not_match :status, :string,
          description: 'Exclude one or many pipeline statuses.',
          max_size: MAX_EXCLUSION_VALUES
        exact_match :source, :string, description: 'Filter by one or many pipeline sources',
          in: FILTERABLE_SOURCES,
          formatter: ->(values) { Array.wrap(values).filter_map { |v| SOURCES[v.to_sym] } }
        exact_not_match :source, :string,
          description: 'Exclude one or many pipeline sources. Pipelines with no source are excluded ' \
            'as well.',
          in: FILTERABLE_SOURCES,
          formatter: ->(values) { Array.wrap(values).filter_map { |v| SOURCES[v.to_sym] } },
          max_size: MAX_EXCLUSION_VALUES
        exact_match :ref, :string, description: 'Filter by one or many pipeline refs'
        exact_not_match :ref, :string,
          description: 'Exclude one or many pipeline refs. Pipelines with no ref are excluded as ' \
            'well.',
          max_size: MAX_EXCLUSION_VALUES
        exact_match :user_id, :string, description: 'Filter by one or many user Global IDs',
          formatter: gid_formatter
        exact_not_match :user_id, :string,
          description: 'Exclude one or many user Global IDs. Pipelines with no triggering user ' \
            'are excluded as well.',
          formatter: gid_formatter, max_size: MAX_EXCLUSION_VALUES
        range :started_at, :datetime, description: 'Filter by pipeline start timestamp'
        range :finished_at, :datetime, description: 'Filter by pipeline finish timestamp'
      end
    end
  end
end
