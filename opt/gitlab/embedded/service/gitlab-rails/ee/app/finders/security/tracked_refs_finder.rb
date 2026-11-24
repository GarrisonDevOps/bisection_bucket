# frozen_string_literal: true

module Security
  class TrackedRefsFinder
    def initialize(project, current_user = nil, params = {})
      @project = project
      @current_user = current_user
      @params = params
    end

    def execute
      return Security::ProjectTrackedContext.none unless can_read_security_refs?

      refs = @project.security_project_tracked_contexts

      filter_by_state(refs)
    end

    private

    attr_reader :project, :current_user, :params

    def filter_by_state(refs)
      case params[:state]
      when 'TRACKED'
        refs.tracked
      when 'UNTRACKED'
        refs.untracked
      else
        refs
      end
    end

    def can_read_security_refs?
      Ability.allowed?(current_user, :read_security_project_tracked_ref, project)
    end
  end
end
