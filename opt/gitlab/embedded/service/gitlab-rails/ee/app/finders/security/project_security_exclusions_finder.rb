# frozen_string_literal: true

# Finder used to retrieve security scanners' exclusions for a project.
#
# Basic usage:
#
#     Security::ProjectSecurityExclusionsFinder.new(current_user, project: project).execute
#
# Filter by scopes:
#
#     Security::ProjectSecurityExclusionsFinder.new(current_user, project: project, params: { active: false }).execute
#
# Arguments:
#   current_user - which user is requesting exclusions.
#   project  -which project to scope to.
#   params:
#     id: integer
#     scanner: string
#     type: string
#     status: string
module Security
  class ProjectSecurityExclusionsFinder
    def initialize(current_user, project:, params: {})
      @current_user = current_user
      @project = project
      @params = params
    end

    def execute
      return ProjectSecurityExclusion.none unless can_read_project_security_exclusions?

      exclusions = project.security_exclusions
      exclusions = by_id(exclusions)
      exclusions = by_scanner(exclusions)
      exclusions = by_type(exclusions)

      by_status(exclusions)
    end

    private

    attr_reader :current_user, :project, :params

    def can_read_project_security_exclusions?
      Ability.allowed?(current_user, :read_project_security_exclusions, project)
    end

    def by_id(exclusions)
      return exclusions if params[:id].nil?

      exclusions.id_in(params[:id])
    end

    def by_scanner(exclusions)
      return exclusions unless params[:scanner]

      exclusions.by_scanner(params[:scanner])
    end

    def by_type(exclusions)
      return exclusions unless params[:type]

      exclusions.by_type(params[:type])
    end

    def by_status(exclusions)
      return exclusions if params[:active].nil?

      exclusions.by_status(params[:active])
    end
  end
end
