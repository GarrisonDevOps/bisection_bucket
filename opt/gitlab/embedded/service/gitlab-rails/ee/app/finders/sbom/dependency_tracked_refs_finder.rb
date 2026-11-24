# frozen_string_literal: true

module Sbom
  # rubocop:disable CodeReuse/ActiveRecord -- Query is specific to this finder
  class DependencyTrackedRefsFinder
    def initialize(project, current_user = nil, params = {})
      @project = project
      @current_user = current_user
      @params = params
    end

    def execute
      return ::Security::ProjectTrackedContext.none unless can_read_dependencies?

      refs = ::Security::ProjectTrackedContext
        .for_project(project.id)
        .code_refs
        .where(id: tracked_context_ids)

      refs = filter_by_search(refs)

      refs.order(context_name: :asc, id: :asc)
    end

    private

    attr_reader :project, :current_user, :params

    def tracked_context_ids
      occurrence_ids = ::Sbom::Occurrence
        .where(project_id: project.id, component_version_id: params[:component_version_id])
        .select(:id)

      ::Sbom::OccurrenceRef
        .where(sbom_occurrence_id: occurrence_ids)
        .select(:security_project_tracked_context_id)
    end

    def filter_by_search(refs)
      return refs if params[:search].blank?

      sanitized = ActiveRecord::Base.sanitize_sql_like(params[:search])
      refs.where(::Security::ProjectTrackedContext.arel_table[:context_name].matches("%#{sanitized}%"))
    end

    def can_read_dependencies?
      Ability.allowed?(current_user, :read_dependency, project)
    end
  end
  # rubocop:enable CodeReuse/ActiveRecord
end
