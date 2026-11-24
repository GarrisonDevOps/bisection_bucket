# frozen_string_literal: true

module Mutations
  module Security
    class ProjectSecurityExclusionDelete < BaseMutation
      graphql_name 'ProjectSecurityExclusionDelete'

      authorize :manage_project_security_exclusions

      authorize_granular_token permissions: :delete_security_exclusion,
        boundary_argument: :id, boundary: :project, boundary_type: :project

      argument :id, ::Types::GlobalIDType[::Security::ProjectSecurityExclusion],
        required: true,
        description: 'Global ID of the exclusion to be deleted.'

      def resolve(id:)
        project_security_exclusion = authorized_find!(id: id)

        unless project_security_exclusion.project.licensed_feature_available?(:security_exclusions)
          raise_resource_not_available_error!
        end

        if project_security_exclusion.destroy
          log_audit_event(current_user, project_security_exclusion.project, project_security_exclusion)

          { errors: [] }
        else
          { errors: errors_on_object(project_security_exclusion) }
        end
      end

      def find_object(id:)
        GitlabSchema.object_from_id(id)
      end

      def log_audit_event(user, project, security_exclusion)
        audit_context = {
          name: 'project_security_exclusion_deleted',
          author: user,
          target: security_exclusion,
          scope: project,
          message: "Deleted a security exclusion with type (#{security_exclusion.type})"
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
