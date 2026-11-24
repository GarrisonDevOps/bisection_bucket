# frozen_string_literal: true

module Security
  module TriageCoverage
    class RecomputeService
      def self.execute(project_ids)
        new(project_ids).execute
      end

      def initialize(project_ids)
        @projects = Project.id_in(project_ids).with_namespaces.with_security_scan_profile_triggers
      end

      def execute
        return if projects.empty?

        Security::InventoryFilters::TriageCapabilitiesUpdateService.execute(project_to_capabilities)
      end

      private

      attr_reader :projects

      def project_to_capabilities
        projects.index_with { |project| capabilities_for(project) }
      end

      def capabilities_for(project)
        capabilities = Security::TriageCoverage::CapabilityBitmask.trigger_types.index_with do |trigger_type|
          capability_for(project, trigger_type)
        end

        Security::TriageCoverage::CapabilityBitmask.encode(capabilities)
      end

      def capability_for(project, trigger_type)
        return sbom_ingested_capability(project) if trigger_type == :sbom_ingested

        ai_triage_capability(project, trigger_type)
      end

      def sbom_ingested_capability(project)
        enabled = DependencyManagement::SecurityUpdate::Eligibility.remediation_profile(project).present?

        [enabled, enabled]
      end

      def ai_triage_capability(project, trigger_type)
        profile = Vulnerabilities::AiTriage::Eligibility.profile_for(project, trigger_type)
        return [false, false] unless profile

        run_mode = Vulnerabilities::AiTriage::Eligibility.configuration_for(project, trigger_type)[:run_mode]

        [true, run_mode.to_s == 'auto']
      end
    end
  end
end
