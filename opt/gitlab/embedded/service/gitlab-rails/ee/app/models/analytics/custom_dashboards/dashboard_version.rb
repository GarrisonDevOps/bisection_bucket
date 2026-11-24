# frozen_string_literal: true

module Analytics
  module CustomDashboards
    class DashboardVersion < ApplicationRecord
      self.table_name = 'custom_dashboard_versions'

      belongs_to :dashboard,
        foreign_key: 'custom_dashboard_id',
        inverse_of: :dashboard_versions
      belongs_to :updated_by, class_name: 'User', optional: true
      belongs_to :organization, class_name: 'Organizations::Organization'

      validates :version_number,
        presence: true,
        numericality: { only_integer: true, greater_than: 0 },
        uniqueness: { scope: :custom_dashboard_id }
      validates :config, presence: true
      validates :config, json_schema: { filename: 'analytics_dashboard', size_limit: 64.kilobytes }
      validate  :config_must_be_json_object
      validates :dashboard, presence: true

      scope :for_custom_dashboards, ->(dashboards) { where(custom_dashboard_id: dashboards) }
      scope :oldest_up_to_version, ->(number) { where(version_number: ..number).order(version_number: :asc) }

      private

      def config_must_be_json_object
        errors.add(:config, 'must be a JSON object') unless config.is_a?(Hash)
      end
    end
  end
end
