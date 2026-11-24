# frozen_string_literal: true

module ComplianceManagement
  class ComplianceViolationDetectionWorker
    include ApplicationWorker
    include Gitlab::Utils::StrongMemoize

    urgency :low
    data_consistency :sticky
    feature_category :compliance_management
    idempotent!
    defer_on_database_health_signal :gitlab_main, [:project_audit_events, :group_audit_events], 1.minute

    def perform(args = {})
      @args = args.with_indifferent_access

      return unless audit_event

      return unless audit_event_has_compliance_controls?

      return unless project || group

      trigger_violation_detection_for_projects
    end

    private

    def trigger_violation_detection_for_projects
      all_projects.find_in_batches(batch_size: 100) do |project_batch| # rubocop: disable CodeReuse/ActiveRecord -- activates because of batch_size
        process_project_batch(project_batch)
      end
    end

    def process_project_batch(projects)
      controls_by_project = ComplianceManagement::ComplianceFramework::ComplianceRequirementsControl
                              .grouped_by_project(projects)

      projects.each do |project|
        project_controls = controls_by_project[project.id] || []
        relevant_controls = project_controls.select do |control|
          compliance_controls_to_check.include?(control.name)
        end

        process_controls_for_project(project, relevant_controls)
      end
    end

    def process_controls_for_project(project, controls)
      controls.each_slice(100) do |control_batch|
        control_batch.each do |control|
          ComplianceManagement::Projects::ViolationDetectionService.new(project, control, audit_event).execute
        rescue StandardError => e
          Gitlab::ErrorTracking.track_exception(
            e,
            project_id: project.id,
            control_id: control.id,
            audit_event_id: audit_event.id
          )
        end
      end
    end

    def audit_event
      audit_event_id, audit_event_class_name = @args.values_at(:audit_event_id, :audit_event_class_name)
      audit_event_class_name.constantize.find_by_id(audit_event_id)
    end
    strong_memoize_attr :audit_event

    def audit_event_has_compliance_controls?
      compliance_controls_to_check.present?
    end

    def compliance_controls_to_check
      audit_event_definition = Gitlab::Audit::Type::Definition.get(audit_event.event_name)
      audit_event_definition&.compliance_controls
    end
    strong_memoize_attr :compliance_controls_to_check

    def project_audit_event?
      audit_event.is_a?(AuditEvents::ProjectAuditEvent)
    end

    def group_audit_event?
      audit_event.is_a?(AuditEvents::GroupAuditEvent)
    end

    def project
      return unless project_audit_event?
      return if audit_event.project.is_a?(Gitlab::Audit::NullEntity)

      audit_event.project
    end
    strong_memoize_attr :project

    def group
      return unless group_audit_event?
      return if audit_event.group.is_a?(Gitlab::Audit::NullEntity)

      audit_event.group
    end
    strong_memoize_attr :group

    def all_projects
      project_audit_event? ? Project.id_in(project.id) : group.all_projects
    end
    strong_memoize_attr :all_projects
  end
end
