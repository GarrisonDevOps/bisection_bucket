# frozen_string_literal: true

module Mutations
  module Vulnerabilities
    module Archival
      class Archive < BaseMutation
        graphql_name 'VulnerabilitiesArchive'

        authorize :admin_vulnerability

        authorize_granular_token permissions: :archive_vulnerability,
          boundary_argument: :project_id, boundary_type: :project

        argument :project_id, ::Types::GlobalIDType[::Project],
          required: true,
          description: 'ID of the project to attach the vulnerability to.'

        argument :date, Types::DateType,
          required: true,
          description: 'Last update date of vulnerabilities being archived.'

        field :status, GraphQL::Types::String,
          null: false,
          description: 'Status of the action.'

        def resolve(project_id:, date:)
          project = authorized_find!(id: project_id)

          ensure_feature_available_for!(project)

          ::Vulnerabilities::Archival::ArchiveWorker.perform_async(project.id, date) # rubocop:disable CodeReuse/Worker -- This is the only place we call the worker

          { status: :ok, errors: [] }
        end

        private

        def ensure_feature_available_for!(project)
          raise_resource_not_available_error! unless ::Vulnerabilities::Archival.enabled_for?(project)
        end
      end
    end
  end
end
