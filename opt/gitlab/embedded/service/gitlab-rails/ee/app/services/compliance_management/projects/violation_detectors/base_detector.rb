# frozen_string_literal: true

module ComplianceManagement
  module Projects
    module ViolationDetectors
      class BaseDetector
        attr_reader :project, :control, :audit_event

        def initialize(project, control, audit_event)
          @project = project
          @control = control
          @audit_event = audit_event
        end

        def detect_violations
          raise NotImplementedError, "Subclasses must implement #detect_violations"
        end

        private

        def create_violation
          ComplianceManagement::Projects::ComplianceViolation.create!(
            project: project,
            namespace_id: project.namespace_id,
            audit_event_id: audit_event.id,
            audit_event_table_name: audit_event.class.table_name,
            compliance_requirements_control_id: control.id,
            status: :detected
          )
        end
      end
    end
  end
end
