# frozen_string_literal: true

module Analytics
  module CustomDashboards
    class Dashboard < ApplicationRecord
      self.table_name = 'custom_dashboards'

      include FromUnion

      belongs_to :namespace, optional: true
      belongs_to :organization, class_name: 'Organizations::Organization', optional: false

      belongs_to :created_by, class_name: 'User', optional: false
      belongs_to :updated_by, class_name: 'User', optional: true

      has_one :search_data,
        class_name: 'Analytics::CustomDashboards::SearchData',
        foreign_key: :custom_dashboard_id,
        inverse_of: :dashboard
      has_many :dashboard_versions,
        class_name: 'Analytics::CustomDashboards::DashboardVersion',
        foreign_key: :custom_dashboard_id,
        inverse_of: :dashboard

      validates :name, presence: true, length: { maximum: 255 },
        uniqueness: { scope: [:organization_id, :namespace_id] }
      validates :description, length: { maximum: 2048 }
      validates :config, presence: true
      validates :config, json_schema: { filename: 'analytics_dashboard', size_limit: 64.kilobytes, detail_errors: true }
      validate :config_must_be_json_object
      validate :config_must_not_have_constraints

      before_validation :default_config_version, if: :config_changed?

      after_update :create_config_version, if: :saved_change_to_config?

      MAX_NAMESPACE_IDS = 100

      scope :order_by_created_at_desc, -> { order(created_at: :desc) }
      scope :by_namespace, ->(namespace_id) { where(namespace_id: namespace_id) }
      scope :by_created_by, ->(user_id) { where(created_by_id: user_id) }
      scope :with_namespace, -> { where.not(namespace_id: nil) }
      scope :org_scoped, ->(organization_id) {
        where(namespace_id: nil, organization_id: organization_id)
      }

      scope :namespace_scoped, ->(organization_id, namespace_ids) {
        where(namespace_id: namespace_ids, organization_id: organization_id)
      }

      scope :search_by_name, ->(query) {
        joins(:search_data)
          .where(
            "#{Analytics::CustomDashboards::SearchData.quoted_table_name}.search_vector @@ plainto_tsquery(:q)",
            q: query
          )
      }

      def self.authorized_namespace_ids_for(user, organization:)
        Analytics::CustomDashboards::AuthorizedNamespaceQuery
          .for(
            user,
            organization: organization,
            min_access_level: Gitlab::Access::REPORTER
          )
          .limit(MAX_NAMESPACE_IDS)
          .pluck(:id)
      end

      def system?
        false
      end

      def slug
        nil
      end

      private

      def config_must_be_json_object
        errors.add(:config, 'must be a JSON object') unless config.is_a?(Hash)
      end

      # Only SystemDashboardPolicy enforces constraints, so a saved dashboard would claim checks nothing applies.
      def config_must_not_have_constraints
        errors.add(:config, 'must not include constraints') if config.is_a?(Hash) && config.key?('constraints')
      end

      def default_config_version
        self.config = config.merge('version' => '2') if config.is_a?(Hash) && !config.key?('version')
      end

      def create_config_version
        last_version = dashboard_versions.order(version_number: :desc).first
        next_version_number = last_version ? last_version.version_number + 1 : 1

        dashboard_versions.create!(
          organization_id: organization_id,
          version_number: next_version_number,
          config: config,
          updated_by_id: updated_by_id
        )
      end
    end
  end
end
