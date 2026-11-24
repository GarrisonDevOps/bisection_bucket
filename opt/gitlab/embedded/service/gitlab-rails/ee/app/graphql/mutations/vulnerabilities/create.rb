# frozen_string_literal: true

module Mutations
  module Vulnerabilities
    class Create < BaseMutation
      graphql_name 'VulnerabilityCreate'

      include Gitlab::InternalEventsTracking

      authorize :admin_vulnerability

      authorize_granular_token permissions: :create_vulnerability,
        boundary_argument: :project,
        boundary_type: :project

      argument :project, ::Types::GlobalIDType[::Project],
        required: true,
        description: 'ID of the project to attach the vulnerability to.'

      argument :name, GraphQL::Types::String,
        required: true,
        description: 'Name of the vulnerability.'

      argument :description, GraphQL::Types::String,
        required: true,
        description: 'Long text section that describes the vulnerability in more detail.'

      argument :scanner, Types::VulnerabilityScannerInputType,
        required: true,
        description: 'Information about the scanner used to discover the vulnerability.'

      argument :identifiers, [Types::VulnerabilityIdentifierInputType],
        required: true,
        validates: { length: { minimum: 1 } },
        description: 'Array of CVE or CWE identifiers for the vulnerability.'

      argument :state, Types::VulnerabilityStateEnum,
        required: false,
        description: 'State of the vulnerability (defaults to `detected`).',
        default_value: 'detected'

      argument :severity, Types::VulnerabilitySeverityEnum,
        required: false,
        description: 'Severity of the vulnerability (defaults to `unknown`).',
        default_value: 'unknown'

      argument :solution, GraphQL::Types::String,
        required: false,
        description: 'Instructions for how to fix the vulnerability.'

      argument :project_tracked_context, Types::Security::ProjectTrackedContextInputType,
        required: false,
        description: 'Tracked context to associate with the vulnerability.'

      argument :detected_at, Types::TimeType,
        required: false,
        description: 'Timestamp of when the vulnerability was first detected (defaults to creation time).'

      argument :confirmed_at, Types::TimeType,
        required: false,
        description: 'Timestamp of when the vulnerability state changed to confirmed (defaults to creation time if status is `confirmed`).'

      argument :resolved_at, Types::TimeType,
        required: false,
        description: 'Timestamp of when the vulnerability state changed to resolved (defaults to creation time if status is `resolved`).'

      argument :dismissed_at, Types::TimeType,
        required: false,
        description: 'Timestamp of when the vulnerability state changed to dismissed (defaults to creation time if status is `dismissed`).'

      field :vulnerability, Types::VulnerabilityType,
        null: true,
        description: 'Vulnerability created.'

      def resolve(**attributes)
        project = authorized_find!(id: attributes.fetch(:project))

        params = build_vulnerability_params(attributes)

        result = ::Vulnerabilities::ManuallyCreateService.new(
          project,
          current_user,
          params: params
        ).execute

        if result.success?
          track_internal_event(
            'manually_create_vulnerability',
            user: current_user,
            project: project,
            additional_properties: {
              label: 'graphql'
            }
          )
        end

        {
          vulnerability: result.payload[:vulnerability],
          errors: result.success? ? [] : result.payload[:errors]
        }
      end

      private

      def build_vulnerability_params(params)
        vulnerability_params = params.slice(
          *%i[
            name
            state
            severity
            description
            solution
            detected_at
            confirmed_at
            resolved_at
            dismissed_at
            identifiers
            scanner
          ])

        if params[:project_tracked_context]
          vulnerability_params[:project_tracked_context_name] = params[:project_tracked_context][:name]
          vulnerability_params[:project_tracked_context_type] = params[:project_tracked_context][:type]
        end

        {
          vulnerability: vulnerability_params
        }
      end
    end
  end
end
