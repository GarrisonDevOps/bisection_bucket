# frozen_string_literal: true

module Vulnerabilities
  module AiTriage
    module Eligibility
      PROFILE_TYPE = :triage_and_remediation

      module_function

      def enabled?(project, trigger_type)
        profile_for(project, trigger_type).present?
      end

      def severity_allowed?(vulnerability, trigger_type)
        project = vulnerability&.project
        return false unless project

        levels = ::Enums::Vulnerability.severity_levels
        threshold = levels[configuration_for(project, trigger_type)[:severity_level]]
        # No threshold means no profile governs this trigger, so keep the gate the
        # `duo_*_enabled` settings path has applied.
        return vulnerability.high_or_critical_severity? unless threshold

        levels.fetch(vulnerability.severity, 0) >= threshold
      end

      def cwe_allowed?(vulnerability, trigger_type)
        project = vulnerability&.project
        return false unless project

        classes = configuration_for(project, trigger_type)[:cwe_classes]
        return true if classes.blank?

        finding_cwes = Array(vulnerability.finding&.identifiers).select(&:cwe?).map { |i| i.name.upcase }
        finding_cwes.intersect?(classes)
      end

      # Call only from the automatic enqueue callbacks. The bulk path reaches the workers directly
      def auto_run?(vulnerability, trigger_type)
        return false unless severity_allowed?(vulnerability, trigger_type)
        return false unless cwe_allowed?(vulnerability, trigger_type)
        return true unless enabled?(vulnerability.project, trigger_type)

        configuration_for(vulnerability.project, trigger_type)[:run_mode].to_s == 'auto'
      end

      def profile_for(project, trigger_type)
        return unless project

        ::Gitlab::SafeRequestStore.fetch([:ai_triage_profile, project.id, trigger_type.to_s]) do
          if ::Feature.enabled?(:triage_and_remediation_profile, project.root_ancestor)
            project.security_scan_profile_for(PROFILE_TYPE, trigger_type)
          end
        end
      end

      def configuration_for(project, trigger_type)
        return {} unless project

        ::Gitlab::SafeRequestStore.fetch([:ai_triage_configuration, project.id, trigger_type.to_s]) do
          profile_for(project, trigger_type)&.effective_configuration_for(trigger_type, project: project) || {}
        end
      end
    end
  end
end
