# frozen_string_literal: true

module Activation
  class Metric < ApplicationRecord
    self.table_name = 'activation_metrics'

    belongs_to :user, optional: false
    belongs_to :namespace, optional: true

    validates :metric, presence: true

    enum :metric, {
      merged_mr: 0 # Example metric, to be used in follow-up MR
    }

    scope :for_user, ->(user) { where(user: user) }
    scope :for_namespace, ->(namespace) { where(namespace: namespace) }
    scope :by_metric, ->(metric) { where(metric: metric) }

    def self.track(metric, user:, namespace: nil)
      return unless Feature.enabled?(:activation_tracking, user, type: :wip)
      return unless metric.present? && user.present?

      record_for(
        user_id: user.id,
        metric: metric,
        namespace_id: namespace&.root_ancestor&.id
      )
    end

    def self.record_for(user_id:, metric:, namespace_id: nil)
      safe_find_or_create_by!(user_id: user_id, namespace_id: namespace_id, metric: metric) # rubocop:disable Performance/ActiveRecordSubtransactionMethods -- Low-traffic, write-once activation metrics
    end

    def self.completed?(user_id:, metric:, namespace_id: nil)
      exists?(user_id: user_id, metric: metric, namespace_id: namespace_id)
    end
  end
end
