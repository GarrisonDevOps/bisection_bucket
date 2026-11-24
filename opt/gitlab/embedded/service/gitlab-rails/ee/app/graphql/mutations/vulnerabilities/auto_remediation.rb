# frozen_string_literal: true

module Mutations
  module Vulnerabilities
    class AutoRemediation < BaseMutation
      graphql_name 'VulnerabilityAutoRemediation'
      description 'Triggers automated remediation for a single vulnerability. Currently supports ' \
        'dependency (SCA) vulnerabilities, where a remediation merge request is created ' \
        'asynchronously when a fix is available; other report types return `UNSUPPORTED`.'

      authorize :admin_vulnerability

      authorize_granular_token permissions: :resolve_vulnerability,
        boundary_argument: :vulnerability_id, boundary: :project,
        boundary_type: :project

      argument :vulnerability_id, ::Types::GlobalIDType[::Vulnerability],
        required: true,
        description: 'ID of the vulnerability to remediate.'

      field :status, ::Types::Vulnerabilities::AutoRemediationStatusEnum,
        null: true,
        description: 'Outcome of triggering auto-remediation.'

      def resolve(vulnerability_id:)
        vulnerability = authorized_find!(id: vulnerability_id)
        project = vulnerability.project

        # Consistent with the scheduled counterpart (SchedulerService): remediation
        # only runs when a remediation configuration is available for the project.
        unless ::DependencyManagement::SecurityUpdate::Eligibility.remediation_profile(project)
          return { status: nil, errors: ['Automated dependency security updates not configured'] }
        end

        # Only SCA (dependency) remediation is implemented today; other report
        # types have no auto-remediation path yet.
        return { status: 'unsupported', errors: [] } unless vulnerability.dependency_scanning?

        sbom_occurrence = ::DependencyManagement::SecurityUpdate::SbomOccurrenceFinder
          .new(project: project, vulnerability: vulnerability)
          .execute
          .first

        return { status: 'unsupported', errors: [] } unless sbom_occurrence

        unless ::DependencyManagement::SecurityUpdate::Eligibility.remediable?(vulnerability)
          return { status: 'no_fix_available', errors: [] }
        end

        request = ::DependencyManagement::SecurityUpdate::Request.new(
          sbom_occurrence: sbom_occurrence,
          vulnerability: vulnerability
        )

        response = ::DependencyManagement::SecurityUpdate::UpdateService
          .new(project: project)
          .execute(request)

        if response.success?
          { status: 'in_progress', errors: [] }
        else
          { status: nil, errors: [response.message] }
        end
      end
    end
  end
end
