# frozen_string_literal: true

module Mutations
  module Security
    class ProjectSecurityExclusionUpdate < BaseMutation
      graphql_name 'ProjectSecurityExclusionUpdate'

      authorize :manage_project_security_exclusions

      authorize_granular_token permissions: :update_security_exclusion,
        boundary_argument: :id, boundary: :project, boundary_type: :project

      argument :id, ::Types::GlobalIDType[::Security::ProjectSecurityExclusion],
        required: true,
        description: 'Global ID of the exclusion to be updated.'

      argument :type,
        Types::Security::ExclusionTypeEnum,
        required: false,
        description: 'Type of the exclusion.'

      argument :scanner,
        Types::Security::ExclusionScannerEnum,
        required: false,
        description: 'Scanner to ignore values for based on the exclusion.'

      argument :value,
        GraphQL::Types::String,
        required: false,
        description: 'Value of the exclusion.'

      argument :active,
        GraphQL::Types::Boolean,
        required: false,
        description: 'Whether the exclusion is active.'

      argument :description,
        GraphQL::Types::String,
        required: false,
        description: 'Optional description for the exclusion.'

      field :security_exclusion,
        Types::Security::ProjectSecurityExclusionType,
        null: true,
        description: 'Project security exclusion updated.'

      def resolve(id:, **args)
        project_security_exclusion = authorized_find!(id: id)

        unless project_security_exclusion.project.licensed_feature_available?(:security_exclusions)
          raise_resource_not_available_error!
        end

        project_security_exclusion.assign_attributes(args.slice(*permitted_params))

        if project_security_exclusion.save
          log_audit_event(current_user, project_security_exclusion.project, project_security_exclusion)

          {
            security_exclusion: project_security_exclusion,
            errors: []
          }
        else
          {
            security_exclusion: nil,
            errors: errors_on_object(project_security_exclusion)
          }
        end
      end

      def find_object(id:)
        GitlabSchema.object_from_id(id)
      end

      def permitted_params
        self.class.own_arguments.keys.map(&:to_sym) - [:id]
      end

      def log_audit_event(user, project, security_exclusion)
        audit_context = {
          name: 'project_security_exclusion_updated',
          author: user,
          target: security_exclusion,
          scope: project,
          message: "Updated a security exclusion with type (#{security_exclusion.type})"
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
