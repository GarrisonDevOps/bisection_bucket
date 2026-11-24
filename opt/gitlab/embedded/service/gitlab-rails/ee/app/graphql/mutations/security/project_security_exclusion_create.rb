# frozen_string_literal: true

module Mutations
  module Security
    class ProjectSecurityExclusionCreate < BaseMutation
      graphql_name 'ProjectSecurityExclusionCreate'

      include FindsProject

      authorize :manage_project_security_exclusions

      authorize_granular_token permissions: :create_security_exclusion,
        boundary_argument: :project_path, boundary_type: :project

      argument :project_path, GraphQL::Types::ID,
        required: true,
        description: 'Full path of the project the exclusion will be associated with.'

      argument :type,
        Types::Security::ExclusionTypeEnum,
        required: true,
        description: 'Type of the exclusion.'

      argument :scanner,
        Types::Security::ExclusionScannerEnum,
        required: true,
        description: 'Scanner to ignore values for based on the exclusion.'

      argument :value,
        GraphQL::Types::String,
        required: true,
        description: 'Value of the exclusion.'

      argument :active,
        GraphQL::Types::Boolean,
        required: true,
        description: 'Whether the exclusion is active.'

      argument :description,
        GraphQL::Types::String,
        required: false,
        description: 'Optional description for the exclusion.'

      field :security_exclusion,
        Types::Security::ProjectSecurityExclusionType,
        null: true,
        description: 'Project security exclusion created.'

      def resolve(project_path:, **args)
        project = authorized_find!(project_path)

        raise_resource_not_available_error! unless project.licensed_feature_available?(:security_exclusions)

        project_security_exclusion = project.security_exclusions.build(args.slice(*permitted_params))

        if project_security_exclusion.save
          log_audit_event(current_user, project, project_security_exclusion)

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

      def permitted_params
        self.class.own_arguments.keys.map(&:to_sym) - %i[project_path]
      end

      def log_audit_event(user, project, security_exclusion)
        audit_context = {
          name: 'project_security_exclusion_created',
          author: user,
          target: security_exclusion,
          scope: project,
          message: "Created a new security exclusion with type (#{security_exclusion.type})"
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
