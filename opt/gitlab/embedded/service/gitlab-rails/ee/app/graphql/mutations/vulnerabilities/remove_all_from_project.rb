# frozen_string_literal: true

module Mutations
  module Vulnerabilities
    class RemoveAllFromProject < BaseMutation
      graphql_name 'VulnerabilitiesRemoveAllFromProject'
      description 'Remove all Vulnerabilities and related information from a given project. ' \
                  '[Introduced](https://gitlab.com/gitlab-org/gitlab/-/issues/412602) in GitLab 16.7'

      argument :project_ids,
        [::Types::GlobalIDType[::Project]],
        required: true,
        description: "IDs of project for which all Vulnerabilities should be removed. " \
                     "The deletion will happen in the background so the changes will not be visible immediately."

      argument :resolved_on_default_branch, GraphQL::Types::Boolean,
        required: false,
        description: 'When set as `true`, deletes only the vulnerabilities no longer detected. ' \
                     'When set as `false`, deletes only the vulnerabilities still detected.'

      field :projects, [Types::ProjectType],
        null: false,
        description: 'Projects for which the deletion was scheduled.'

      def resolve(project_ids: [], resolved_on_default_branch: nil)
        raise_not_enough_arguments_error! if project_ids.empty?

        projects = find_projects(project_ids)

        service = ::Vulnerabilities::ScheduleRemovingAllFromProjectService.new(projects, resolved_on_default_branch)
        result = service.execute

        {
          projects: result.payload[:projects],
          errors: result.success? ? [] : Array(result.message)
        }
      end

      private

      def raise_not_enough_arguments_error!
        raise Gitlab::Graphql::Errors::ArgumentError, "at least one Project ID is needed"
      end

      def find_projects(project_ids)
        ids = project_ids.map(&:model_id).uniq.compact.map(&:to_i)
        projects = Project.id_in(ids)
        allowed, forbidden = projects.partition { |p| Ability.allowed?(current_user, :admin_vulnerability, p) }
        raise_resource_not_available_error! unless forbidden.empty?

        allowed
      end
    end
  end
end
