# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    class ProjectControlComplianceStatus < ApplicationRecord
      belongs_to :compliance_requirements_control
      belongs_to :project
      belongs_to :namespace
      belongs_to :compliance_requirement
      belongs_to :requirement_status,
        class_name: '::ComplianceManagement::ComplianceFramework::ProjectRequirementComplianceStatus', optional: true

      enum :status, ::Enums::ComplianceManagement::ComplianceFramework::ProjectControlComplianceStatus.status

      validates :project_id, uniqueness: { scope: :compliance_requirements_control_id }
      # Presence check on a belongs_to loads the record. These columns are NOT NULL with foreign keys, so
      # validating the ids keeps referential integrity without a query per attribute on every save.
      validates_presence_of :status, :project_id, :namespace_id, :compliance_requirement_id,
        :compliance_requirements_control_id

      validate :control_belongs_to_requirement
      validate :framework_applied_to_project
      validate :project_belongs_to_same_namespace
      validate :validate_requirement_status

      scope :for_project_and_control, ->(project_id, control_id) {
        where(project_id: project_id, compliance_requirements_control_id: control_id)
      }

      scope :for_projects, ->(project_ids) {
        where(project_id: project_ids)
      }

      scope :for_requirements, ->(requirement_ids) {
        where(compliance_requirement_id: requirement_ids)
      }

      def self.create_or_find_for_project_and_control(project, control)
        record = for_project_and_control(project.id, control.id).first
        return record if record.present?

        create!(
          compliance_requirements_control: control,
          project: project,
          compliance_requirement_id: control.compliance_requirement_id,
          namespace_id: project.namespace_id,
          status: :pending
        )
      rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordInvalid => e
        if e.is_a?(ActiveRecord::RecordNotUnique) ||
            (e.is_a?(ActiveRecord::RecordInvalid) && e.record&.errors&.of_kind?(:project_id, :taken))
          for_project_and_control(project.id, control.id).first
        else
          raise e
        end
      end

      def self.control_coverage_statistics(project_ids)
        for_projects(project_ids)
          .group(:status)
          .count
      end

      private

      def control_belongs_to_requirement
        return unless compliance_requirements_control_id_changed? || compliance_requirement_id_changed?

        return if compliance_requirement_id.nil? || compliance_requirements_control.nil? ||
          compliance_requirements_control.compliance_requirement_id == compliance_requirement_id

        errors.add(:compliance_requirements_control, _("must belong to the compliance requirement."))
      end

      def framework_applied_to_project
        return unless project_id_changed? || compliance_requirement_id_changed?
        return if project.nil? || compliance_requirement.nil?

        return if ComplianceManagement::ComplianceFramework::ProjectSettings.by_framework_and_project(project.id,
          compliance_requirement.framework.id).exists?

        errors.add(:project, _("should have the compliance requirement's framework applied to it."))
      end

      def project_belongs_to_same_namespace
        return unless project_id_changed? || namespace_id_changed?
        return if namespace_id.nil? || project.nil? || project.namespace_id == namespace_id

        errors.add(:project, _("must belong to the same namespace."))
      end

      def validate_requirement_status
        return if requirement_status_id.nil?

        return if requirement_status.compliance_requirement_id == compliance_requirement_id

        errors.add(:requirement_status, _("must belong to the same compliance requirement."))
      end
    end
  end
end
