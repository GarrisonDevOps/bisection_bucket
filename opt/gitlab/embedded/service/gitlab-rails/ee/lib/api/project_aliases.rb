# frozen_string_literal: true

module API
  class ProjectAliases < ::API::Base
    include PaginationParams

    feature_category :source_code_management

    before { check_feature_availability }
    before { authenticated_as_admin! }

    helpers do
      def project_alias
        ProjectAlias.find_by_name!(params[:name])
      end

      def project
        find_project!(params[:project_id])
      end

      def check_feature_availability
        forbidden! unless ::License.feature_available?(:project_aliases)
      end
    end

    resource :project_aliases do
      desc 'List all project aliases' do
        detail 'Lists all project aliases for the instance.'
        success code: 200, model: ::API::Entities::ProjectAlias
        is_array true
        failure [
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[project_alias]
      end
      params do
        use :pagination
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_project_alias, boundary_type: :instance,
        assignable_when: [:admin]
      get do
        present paginate(ProjectAlias.all), with: ::API::Entities::ProjectAlias
      end

      desc 'Retrieve a project alias' do
        detail 'Retrieves details of a specified project alias.'
        success code: 200, model: ::API::Entities::ProjectAlias
        failure [
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[project_alias]
      end
      params do
        requires :name, type: String, desc: 'Name of the alias. Must be unique.'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :read_project_alias, boundary_type: :instance,
        assignable_when: [:admin]
      get ':name' do
        present project_alias, with: ::API::Entities::ProjectAlias
      end

      desc 'Create a project alias' do
        detail 'Creates a project alias.'
        success code: 201, model: ::API::Entities::ProjectAlias
        failure [
          { code: 400, message: 'Bad request' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[project_alias]
      end
      params do
        requires :project_id,
          type: String,
          desc: 'ID or URL-encoded path of the project.',
          documentation: { example: 'gitlab-org/gitlab' }
        requires :name,
          type: String,
          desc: 'Name of the alias. Must be unique.',
          documentation: { example: 'gitlab' }
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :create_project_alias, boundary_type: :instance,
        assignable_when: [:admin]
      post do
        project_alias = project.project_aliases.create(name: params[:name])

        if project_alias.valid?
          present project_alias, with: ::API::Entities::ProjectAlias
        else
          render_validation_error!(project_alias)
        end
      end

      desc 'Delete a project alias' do
        detail 'Deletes a specified project alias. Administrators only.'
        success code: 204
        failure [
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[project_alias]
      end
      params do
        requires :name, type: String, desc: 'Name of the alias. Must be unique.'
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :delete_project_alias, boundary_type: :instance,
        assignable_when: [:admin]
      delete ':name' do
        project_alias.destroy

        no_content!
      end
    end
  end
end
