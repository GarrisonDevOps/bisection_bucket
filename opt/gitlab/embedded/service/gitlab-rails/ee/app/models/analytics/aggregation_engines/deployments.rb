# frozen_string_literal: true

module Analytics
  module AggregationEngines
    class Deployments < Gitlab::Database::Aggregation::ClickHouse::Engine
      self.table_name = 'siphon_deployments'

      include Support::BaseAggregationScope

      STATUSES = ::Deployment.statuses.freeze
      FINISHED_STATUS_INTS = STATUSES.values_at(:success, :failed, :canceled).join(', ').freeze

      transient(:is_finished_status) { sql("status IN (#{FINISHED_STATUS_INTS})") }
      transient(:duration_ms) do
        sql(
          'multiIf(isNotNull(finished_at),
          toUnixTimestamp64Milli(assumeNotNull(finished_at)) - toUnixTimestamp64Milli(created_at),
          NULL)'
        )
      end

      dimensions do
        column :status, :string, description: 'Deployment status',
          formatter: ->(value) { ::Deployment.statuses.key(value) }
        column :environment_id, :integer, description: 'Environment ID', association: true
        column :ref, :string, description: 'Deployment ref'
        # user_id is nullable, so rows without a user group under a null key.
        column :user_id, :integer,
          description: 'User who created the deployment. Returns `null` if there is no recorded creator, ' \
            'or if that user has been deleted',
          association: true
        date_bucket :created_at, :date, description: 'Deployment creation date'
        date_bucket :finished_at, :date, description: 'Deployment finish date'
      end

      metrics do
        count description: 'Total number of deployments'

        # DEPRECATED: use the `duration` measurement instead
        quantile :deployment_duration, :float, transient(:duration_ms),
          description: 'Deployment duration quantile in milliseconds',
          parameters: {
            quantile: { type: :float, in: 0.0..1.0 }
          }

        rate :success,
          numerator_if: ->(_params) { sql("status = #{STATUSES[:success]}") },
          denominator_if: transient(:is_finished_status),
          description: 'Deployment success rate (out of finished deployments)'

        rate :failure,
          numerator_if: ->(_params) { sql("status = #{STATUSES[:failed]}") },
          denominator_if: transient(:is_finished_status),
          description: 'Deployment failure rate (out of finished deployments)'

        rate :canceled,
          numerator_if: ->(_params) { sql("status = #{STATUSES[:canceled]}") },
          denominator_if: transient(:is_finished_status),
          description: 'Deployment canceled rate (out of finished deployments)'
      end

      measurement :duration, :integer, -> {
        sql('multiIf(isNotNull(finished_at), toInt64(ceil(
            (toUnixTimestamp64Milli(assumeNotNull(finished_at)) - toUnixTimestamp64Milli(created_at)) / 1000
          )), NULL)')
      }, description: 'Deployment duration in seconds'

      filters do
        exact_match :status, :string, description: 'Filter by one or many deployment statuses',
          in: STATUSES.keys,
          formatter: ->(values) { Array.wrap(values).filter_map { |v| ::Deployment.statuses[v] } }
        exact_not_match :status, :string,
          description: 'Exclude one or many deployment statuses.',
          in: STATUSES.keys,
          formatter: ->(values) { Array.wrap(values).filter_map { |v| ::Deployment.statuses[v] } },
          max_size: MAX_EXCLUSION_VALUES
        exact_match :environment_id, :string, description: 'Filter by one or many environment Global IDs',
          formatter: gid_formatter
        exact_not_match :environment_id, :string,
          description: 'Exclude one or many environment Global IDs.',
          formatter: gid_formatter, max_size: MAX_EXCLUSION_VALUES
        exact_match :ref, :string, description: 'Filter by one or many deployment refs'
        exact_not_match :ref, :string,
          description: 'Exclude one or many deployment refs.',
          max_size: MAX_EXCLUSION_VALUES
        exact_match :user_id, :string, description: 'Filter by one or many user Global IDs',
          formatter: gid_formatter
        exact_not_match :user_id, :string,
          description: 'Exclude one or many user Global IDs. Deployments with no triggering user ' \
            'are excluded as well.',
          formatter: gid_formatter, max_size: MAX_EXCLUSION_VALUES
        range :created_at, :datetime, description: 'Filter by deployment creation timestamp'
        range :finished_at, :datetime, description: 'Filter by deployment finish timestamp'
      end
    end
  end
end
