# frozen_string_literal: true

module Analytics
  module Dashboards
    class DashboardsPointer < ApplicationRecord
      self.table_name = 'analytics_dashboards_pointers'

      belongs_to :namespace
      belongs_to :project
      belongs_to :target_project, optional: false, class_name: 'Project'

      validates_with ExactlyOnePresentValidator, fields: [:namespace, :project]
      # Avoid breaking existing records. The read endpoint also "validates" (returns nil if invalid)
      # the presence of the target_project_id in the group hierarchy.
      validate :check_target_project_presence_in_hierarchy

      validates :namespace_id, uniqueness: { scope: :project_id }, if: :namespace_id?
      validates :project_id, uniqueness: { scope: :namespace_id }, if: :project_id?

      private

      def check_target_project_presence_in_hierarchy
        resource = project || namespace
        return if resource.nil?
        return if target_project_id.blank? || !target_project_id_changed?
        return if resource.root_ancestor.all_projects.exists?(id: target_project_id)

        errors.add(:base, _('The selected project is not available'))
      end
    end
  end
end
