# frozen_string_literal: true

module AuditEvents
  class ComplianceViolationScheduler
    attr_reader :audit_events

    def initialize(audit_events)
      @audit_events = audit_events
    end

    def execute
      audit_events.each do |audit_event|
        schedule_compliance_check(audit_event)
      end
    end

    private

    def schedule_compliance_check(audit_event)
      return unless should_schedule_compliance_check?(audit_event)

      event_definition = Gitlab::Audit::Type::Definition.get(audit_event.event_name)
      return unless event_definition&.compliance_controls.present?

      ::ComplianceManagement::ComplianceViolationDetectionWorker.perform_async(
        { 'audit_event_id' => audit_event.id, 'audit_event_class_name' => audit_event.class.name })
    end

    def should_schedule_compliance_check?(audit_event)
      return false unless audit_event.entity
      return false if audit_event.entity.is_a?(Gitlab::Audit::NullEntity)

      unless audit_event.event_name.present?
        Gitlab::AppLogger.info(
          message: "Audit event without event_name encountered in compliance scheduler",
          audit_event_id: audit_event.id,
          audit_event_class: audit_event.class.name
        )
        return false
      end

      if audit_event.entity_type == 'Project'
        audit_event.project.licensed_feature_available?(:project_level_compliance_violations_report)
      elsif audit_event.entity_type == 'Group'
        audit_event.group.licensed_feature_available?(:group_level_compliance_violations_report)
      end
    end
  end
end
