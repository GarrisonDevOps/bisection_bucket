# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    # Shared eligibility rules for automated dependency security updates.
    #
    # Used both by the automatic SchedulerService and by the user-triggered
    # single-vulnerability remediation flow, so the rules stay in one place.
    module Eligibility
      # Auto Remediation is only supported for a limited set of package managers.
      SUPPORTED_PACKAGE_MANAGERS = %w[bundler maven gradle pip pipenv poetry setuptools uv npm yarn pnpm bun go
        cargo nuget pub swift].freeze

      # Scan profile types that can carry the remediation configuration, wired to
      # the sbom-ingestion trigger.
      REMEDIATION_PROFILE_TYPES = Enums::Security.remediation_scan_profile_types.keys.freeze
      REMEDIATION_TRIGGER_TYPE = :sbom_ingested

      # This regex is used to filter out vulnerabilities that have a non-empty
      # solution string that simply states that there's **not** a solution.
      # Unfortunately, we made a decision some time ago to include a templated
      # solution for vulnerabilities that do not have a solution which, means
      # that we cannot simply filter out vulnerabilities with empty solution when
      # we're querying the database. Instead, we have to filter things out on the
      # client side with this regex.
      UNKNOWN_SOLUTION_REGEX = /^Unfortunately,?\s*there is no solution available/i

      # Postgres form of UNKNOWN_SOLUTION_REGEX for `~*` / `!~*`. `(?n)` makes `^` match at line
      # starts. The pattern sticks to syntax both engines support; Postgres `\s` may match a wider whitespace set.
      UNKNOWN_SOLUTION_SQL_REGEX = "(?n)#{UNKNOWN_SOLUTION_REGEX.source}".freeze

      module_function

      # Whether a fix is available for the given vulnerability, derived from its
      # solution string (there is no precomputed "fix available" signal).
      def remediable?(vulnerability)
        solution = vulnerability.solution
        solution.present? && !UNKNOWN_SOLUTION_REGEX.match?(solution)
      end

      # Requests always target the default branch, and registry image scans report container
      # contents with no manifest in the repository, so neither should start a run.
      def trigger_pipeline?(pipeline)
        pipeline.default_branch? && !pipeline.container_registry_push?
      end

      # The remediation scan profile for the project, or nil when none is
      # available. Both the automatic scheduler and the user-triggered
      # remediation flow gate on this so the two stay consistent about when
      # remediation may run.
      def remediation_profile(project)
        return unless project

        project.security_scan_profile_for(REMEDIATION_PROFILE_TYPES, REMEDIATION_TRIGGER_TYPE)
      end

      def remediation_configuration(project, profile: nil)
        profile ||= remediation_profile(project)

        profile&.effective_configuration_for(REMEDIATION_TRIGGER_TYPE, project: project) || {}
      end
    end
  end
end
