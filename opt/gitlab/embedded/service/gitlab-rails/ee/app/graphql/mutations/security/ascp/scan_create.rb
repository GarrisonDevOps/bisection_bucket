# frozen_string_literal: true

module Mutations
  module Security
    module Ascp
      class ScanCreate < BaseMutation
        graphql_name 'AscpScanCreate'

        include FindsProject

        authorize :create_ascp_scan

        authorize_granular_token permissions: :create_ascp_scan,
          boundary_argument: :project_path, boundary_type: :project

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        argument :project_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the project.'

        argument :commit_sha, GraphQL::Types::String,
          required: true,
          description: 'Git commit SHA that was scanned.'

        argument :scan_type, Types::Security::Ascp::ScanTypeEnum,
          required: false,
          default_value: 'full',
          replace_null_with_default: true,
          description: 'Type of scan (default: full).'

        argument :base_scan_id, ::Types::GlobalIDType[::Security::Ascp::Scan],
          required: false,
          description: 'ID of the base scan for incremental scans.'

        argument :base_commit_sha, GraphQL::Types::String,
          required: false,
          description: 'Base commit SHA for incremental scans.'

        field :scan, Types::Security::Ascp::ScanType,
          null: true,
          description: 'Created scan.',
          experiment: { milestone: '18.10' },
          scopes: [:api, :ai_workflows]

        def resolve(project_path:, base_scan_id: nil, **args)
          project = authorized_find!(project_path)

          params = args.merge(
            base_scan_id: base_scan_id&.model_id
          )

          result = ::Security::Ascp::CreateScanService.new(
            current_user: current_user, project: project, params: params
          ).execute

          {
            scan: result.success? ? result.payload[:scan] : nil,
            errors: result.errors
          }
        end
      end
    end
  end
end
