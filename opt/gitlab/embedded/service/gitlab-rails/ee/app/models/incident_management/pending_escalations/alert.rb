# frozen_string_literal: true

module IncidentManagement
  module PendingEscalations
    class Alert < ApplicationRecord
      include ::IncidentManagement::BasePendingEscalation

      self.table_name = 'incident_management_pending_alert_escalations'

      belongs_to :alert, class_name: 'AlertManagement::Alert', foreign_key: 'alert_id', inverse_of: :pending_escalations
      alias_method :target, :alert

      validates :rule_id, uniqueness: { scope: [:alert_id] }

      scope :for_target, ->(alerts) { where(alert_id: alerts) }

      def self.class_for_check_worker
        AlertCheckWorker
      end

      def escalatable
        alert
      end

      def type
        :alert
      end
    end
  end
end
