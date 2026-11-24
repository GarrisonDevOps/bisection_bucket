# frozen_string_literal: true

module GitlabSubscriptions
  class UpcomingReconciliation < ApplicationRecord
    include SafelyChangeColumnDefault

    columns_changing_default :organization_id

    self.table_name = 'upcoming_reconciliations'

    belongs_to :namespace, inverse_of: :upcoming_reconciliation, optional: true
    belongs_to :organization, class_name: 'Organizations::Organization'

    # Validate presence of namespace_id if this is running on a GitLab instance
    # that has paid namespaces.
    validates :namespace,
      uniqueness: { unless: proc { ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) } },
      presence: { if: proc { ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) } }
    validates :next_reconciliation_date, :display_alert_from, presence: true

    scope :by_namespace_ids, ->(namespace_ids) { where(namespace_id: namespace_ids) }

    def self.next(namespace_id = nil)
      if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        return unless namespace_id

        self.find_by(namespace_id: namespace_id)
      else
        self.find_by(namespace_id: nil)
      end
    end

    def display_alert?
      next_reconciliation_date >= Date.current && display_alert_from <= Date.current
    end
  end
end
