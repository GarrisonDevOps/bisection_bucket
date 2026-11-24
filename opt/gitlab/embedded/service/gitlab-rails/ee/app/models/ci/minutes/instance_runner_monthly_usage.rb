# frozen_string_literal: true

module Ci
  module Minutes
    # Track compute usage at the runner level.
    class InstanceRunnerMonthlyUsage < Ci::ApplicationRecord
      include Ci::NamespacedModelName

      belongs_to :root_namespace, class_name: 'Namespace', inverse_of: :instance_runner_monthly_usages
      belongs_to :project, class_name: 'Project', inverse_of: :instance_runner_monthly_usages
      belongs_to :runner, class_name: 'Ci::Runner', inverse_of: :instance_runner_monthly_usages

      validates :root_namespace, presence: true
      validates :project, presence: true, on: :create
      validates :runner, presence: true, on: :create
      validates :billing_month, presence: true
      validates :compute_minutes_used,
        numericality: { greater_than_or_equal_to: 0, allow_nil: false, only_float: true },
        presence: true
      validates :runner_duration_seconds,
        numericality: {
          greater_than_or_equal_to: 0,
          allow_nil: false,
          only_integer: true
        },
        presence: true
      validate :validate_billing_month_format

      private

      def validate_billing_month_format
        return if billing_month.blank?

        return if billing_month == billing_month.beginning_of_month && billing_month.day == 1

        errors.add(:billing_month, 'must be the first day of the month')
      end
    end
  end
end
