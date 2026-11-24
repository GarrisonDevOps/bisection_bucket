# frozen_string_literal: true

module Mutations
  module Projects
    class UpdateComplianceFrameworks < BaseMutation
      graphql_name 'ProjectUpdateComplianceFrameworks'
      description 'Update compliance frameworks for a project.'

      MAX_FRAMEWORKS = 10

      authorize :admin_compliance_framework
      authorize_granular_token permissions: :update_compliance_framework,
        boundary_argument: :project_id, boundary_type: :project

      argument :project_id, Types::GlobalIDType[::Project],
        required: true,
        description: 'ID of the project to change the compliance framework of.'

      argument :compliance_framework_ids, [Types::GlobalIDType[::ComplianceManagement::Framework]],
        required: true,
        description: 'IDs of the compliance framework to update for the project.'

      field :project,
        Types::ProjectType,
        null: true,
        description: "Project after mutation."

      def ready?(**args)
        if args[:compliance_framework_ids].size > MAX_FRAMEWORKS
          raise Gitlab::Graphql::Errors::ArgumentError,
            format(
              _('No more than %{max_frameworks} compliance frameworks can be updated at the same time.'),
              max_frameworks: MAX_FRAMEWORKS
            )
        end

        super
      end

      def resolve(project_id:, compliance_framework_ids:)
        project = GitlabSchema.find_by_gid(project_id).sync

        authorize!(project)

        compliance_frameworks = compliance_frameworks(compliance_framework_ids)

        service_response = ::ComplianceManagement::Frameworks::UpdateProjectService
                             .new(project, current_user, compliance_frameworks)
                             .execute

        { project: project, errors: errors_on_object(project) + service_response.errors }
      end

      private

      def compliance_frameworks(compliance_framework_ids)
        ids = GitlabSchema.parse_gids(compliance_framework_ids).map(&:model_id).map(&:to_i).uniq
        frameworks = ::ComplianceManagement::Framework.id_in(ids)

        if frameworks.length != ids.length
          raise Gitlab::Graphql::Errors::ArgumentError, format(_("Framework id(s) %{missing_ids} are invalid."),
            missing_ids: (ids - frameworks.pluck(:id))) # rubocop: disable CodeReuse/ActiveRecord -- Using pluck only
        end

        frameworks
      end
    end
  end
end
