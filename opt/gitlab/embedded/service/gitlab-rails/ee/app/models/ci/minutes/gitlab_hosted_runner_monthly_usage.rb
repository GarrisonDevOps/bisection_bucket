# frozen_string_literal: true

module Ci
  module Minutes
    # Track compute usage at the runner level.
    # For gitlab dedicated hosted runners only
    class GitlabHostedRunnerMonthlyUsage < Ci::ApplicationRecord
      include Ci::NamespacedModelName
      include LooseIndexScan

      belongs_to :project, inverse_of: :hosted_runner_monthly_usages
      belongs_to :root_namespace, class_name: 'Namespace', inverse_of: :hosted_runner_monthly_usages
      belongs_to :runner, class_name: 'Ci::Runner', inverse_of: :hosted_runner_monthly_usages

      validates_uniqueness_of :billing_month, scope: %i[root_namespace_id runner_id project_id]
      validates :runner, presence: true, on: :create
      validates :project, presence: true, on: :create
      validates :root_namespace, presence: true, on: :create

      validates :billing_month, presence: true
      validates :compute_minutes_used,
        numericality: { greater_than_or_equal_to: 0, allow_nil: false, only_float: true },
        presence: true
      validates :runner_duration_seconds, numericality: {
        greater_than_or_equal_to: 0,
        allow_nil: false,
        only_integer: true
      }
      validate :validate_billing_month_format

      scope :instance_aggregate, ->(billing_month, year, runner_id = nil) do
        query = select("TO_CHAR(billing_month, 'FMMonth YYYY') AS billing_month_formatted",
          'billing_month AS billing_month',
          'TO_CHAR(DATE_TRUNC(\'month\', billing_month), \'YYYY-MM-DD\') AS billing_month_iso8601',
          'SUM(compute_minutes_used) AS compute_minutes',
          'SUM(runner_duration_seconds) AS duration_seconds',
          'NULL as root_namespace_id')
        .where(billing_month: billing_month_range(billing_month, year))
        .group(:billing_month)
        .order(billing_month: :desc)

        query = query.where(runner_id: runner_id) if runner_id.present?
        query
      end

      scope :per_root_namespace, ->(billing_month, year, runner_id = nil) do
        query = where(billing_month: billing_month_range(billing_month, year))
          .group(:billing_month, :root_namespace_id)
          .select("TO_CHAR(billing_month, 'FMMonth YYYY') AS billing_month_formatted",
            'billing_month AS billing_month',
            'TO_CHAR(DATE_TRUNC(\'month\', billing_month), \'YYYY-MM-DD\') AS billing_month_iso8601',
            'root_namespace_id',
            'SUM(compute_minutes_used) AS compute_minutes',
            'SUM(runner_duration_seconds) AS duration_seconds')
          .order(billing_month: :desc, root_namespace_id: :asc)

        query = query.where(runner_id: runner_id) if runner_id.present?
        query
      end

      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- This will be done on GitLab dedicated only. Result set would be small.
      scope :distinct_runner_ids, -> do
        loose_index_scan(column: :runner_id)
          .pluck(:runner_id)
      end
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit

      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- Result set is small.
      scope :distinct_years, -> do
        distinct
          .pluck(Arel.sql('EXTRACT(YEAR FROM billing_month)::integer'))
          .sort
      end
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit

      def self.find_or_create_current(root_namespace_id:, project_id:, runner_id:)
        find_by_params = {
          root_namespace_id: root_namespace_id,
          project_id: project_id,
          runner_id: runner_id,
          billing_month: Time.current.beginning_of_month
        }
        find_or_create_by!(**find_by_params)
      # Handle race condition at the database level
      rescue ActiveRecord::RecordNotUnique
        find_by(**find_by_params)
      end

      def self.billing_month_range(billing_month, year)
        if billing_month.present?
          start_date = billing_month
          end_date = start_date.end_of_month
        else
          year ||= Time.current.year
          start_date = Date.new(year, 1, 1)
          end_date = Date.new(year, 12, 31)
        end

        start_date..end_date
      end

      def increase_usage(compute_minutes: 0, duration: 0)
        increment_params = {}
        increment_params[:compute_minutes_used] = compute_minutes if compute_minutes > 0
        increment_params[:runner_duration_seconds] = duration if duration > 0

        return if increment_params.empty?

        # The use of `update_counters` puts the math within a sql query
        # i.e. compute_minutes_used = COALESCE(compute_minutes_used, 0) + 5
        # This is better for concurrent updates.
        self.class.update_counters(self, increment_params)
      end

      private

      def validate_billing_month_format
        return if billing_month.blank?

        return if billing_month == billing_month.beginning_of_month

        errors.add(:billing_month, 'must be the first day of the month')
      end
    end
  end
end
