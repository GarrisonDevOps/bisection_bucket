# frozen_string_literal: true

module Vulnerabilities
  class SeverityOverrideAuditService
    AUDIT_EVENT_NAME = 'vulnerability_severity_override'

    def initialize(vulnerabilities_audit_attrs:, now:, current_user:, new_severity:)
      @vulnerabilities_audit_attrs = vulnerabilities_audit_attrs
      @now = now
      @current_user = current_user
      @new_severity = new_severity
    end

    def execute
      return if @vulnerabilities_audit_attrs.empty?

      push_events_to_queue(build_projects_events)
    end

    private

    def build_projects_events
      projects_events = Hash.new { |hash, key| hash[key] = [] }

      @vulnerabilities_audit_attrs.each do |vulnerability_attrs|
        project, vulnerability, old_severity = extract_attributes(vulnerability_attrs)
        next unless project.present? && vulnerability.present? && old_severity.present?

        projects_events[project] << build_audit_event(project, vulnerability, old_severity)
      end

      projects_events
    end

    def extract_attributes(vulnerability_attrs)
      vulnerability_attrs.values_at(:project, :vulnerability, :old_severity)
    end

    def build_audit_event(project, vulnerability, old_severity)
      AuditEvents::BuildService.new(
        author: @current_user,
        scope: project,
        target: project,
        created_at: @now,
        message: build_message(old_severity),
        target_details: vulnerability_url(project, vulnerability),
        additional_details: {
          name: AUDIT_EVENT_NAME
        }
      ).execute
    end

    def build_message(old_severity)
      "Vulnerability severity was changed from #{old_severity.capitalize} to #{@new_severity.capitalize}"
    end

    def audit_context(project)
      {
        author: @current_user,
        scope: project,
        target: project,
        name: AUDIT_EVENT_NAME
      }
    end

    def push_events_to_queue(projects_events)
      total_events = 0

      projects_events.each do |project, events|
        ::Gitlab::Audit::Auditor.audit(audit_context(project)) do
          events.each do |event|
            ::Gitlab::Audit::EventQueue.push(event)
          end
          total_events += events.size
        end
      end

      total_events
    end

    def vulnerability_url(project, vulnerability)
      ::Gitlab::Routing.url_helpers.project_security_vulnerability_url(project, vulnerability)
    end
  end
end
