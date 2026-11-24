# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    class ProjectSettings < ApplicationRecord
      self.table_name = 'project_compliance_framework_settings'

      MAX_COMPLIANCE_FRAMEWORKS_PER_PROJECT_COUNT = 20
      PROJECT_EVALUATOR_WORKER_DELAY = 5.minutes

      belongs_to :project
      belongs_to :compliance_management_framework, class_name: "ComplianceManagement::Framework", foreign_key: :framework_id

      validates :project, presence: true
      validate :frameworks_count_per_project

      delegate :full_path, to: :project

      scope :by_framework_and_project, ->(project_id, framework_id) { where(project_id: project_id, framework_id: framework_id) }
      scope :by_project_id, ->(project_id) { where(project_id: project_id) }

      def self.find_or_create_by_project(project, framework)
        find_or_initialize_by(project: project).tap do |setting|
          setting.framework_id = framework.id
          setting.save
        end
      end

      def self.covered_projects_count(project_ids)
        by_project_id(project_ids).distinct.count(:project_id)
      end

      def self.delete_by_framework(framework_ids)
        delete_by(framework_id: framework_ids)
      end

      def self.framework_project_mappings(framework_ids)
        return {} if framework_ids.blank?

        # framework_ids is already limited by the batch size in the worker (100)
        # so this is safe from the RuboCop perspective.
        # Project IDs are sorted so batches stay stable across scheduler runs,
        # letting job deduplication match them.
        where(framework_id: framework_ids)
          .pluck(:framework_id, :project_id) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- batch size controlled by caller
          .group_by(&:first)
          .transform_values { |pairs| pairs.map(&:last).sort }
      end

      private

      def frameworks_count_per_project
        if project.nil? || project.compliance_framework_settings.count < MAX_COMPLIANCE_FRAMEWORKS_PER_PROJECT_COUNT
          return
        end

        errors.add(:project, format(_("cannot have more than %{count} frameworks"),
          count: MAX_COMPLIANCE_FRAMEWORKS_PER_PROJECT_COUNT))
      end
    end
  end
end
