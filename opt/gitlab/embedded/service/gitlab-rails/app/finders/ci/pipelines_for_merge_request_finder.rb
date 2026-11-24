# frozen_string_literal: true

module Ci
  # A state object to centralize logic related to merge request pipelines
  class PipelinesForMergeRequestFinder
    include Gitlab::Utils::StrongMemoize

    COMMITS_LIMIT = 100

    def initialize(merge_request, current_user)
      @merge_request = merge_request
      @current_user = current_user
    end

    attr_reader :merge_request, :current_user

    delegate :recent_diff_head_shas, :commit_shas, :target_project, :source_project, :source_branch, to: :merge_request

    # Fetch all pipelines that the user can read.
    def execute
      if can_read_pipeline_in_target_project? && can_read_pipeline_in_source_project?
        all
      elsif can_read_pipeline_in_source_project?
        pipelines_for(source_project)
      elsif can_read_pipeline_in_target_project?
        pipelines_for(target_project)
      else
        Ci::Pipeline.none
      end
    end

    # Fetch all pipelines without permission check.
    def all
      strong_memoize(:all_pipelines) { pipelines_for }
    end

    # `Ci::PipelinesFinder` returns no pipelines unless the user can read its
    # project. Prefer the source project, and fall back to the target project.
    def authorizing_project
      return source_project if can_read_pipeline_in_source_project?

      target_project
    end

    private

    # Build the readable pipelines, optionally scoped to a single authorized project.
    # `#all` passes no project (both source and target); the fork partial-permission
    # paths pass the one project the user can read.
    def pipelines_for(project = nil)
      return Ci::Pipeline.none unless source_project

      pipelines =
        if merge_request.persisted?
          merge_request_pipelines(project)
        elsif include_source_branch?(project)
          triggered_for_branch.for_sha(commit_shas)
        else
          Ci::Pipeline.none
        end

      sort(pipelines)
    end

    def merge_request_pipelines(project)
      # When a single project is given, scope by equality (`project_id = <project>`)
      # so the planner picks the selective merge_request_id index instead of a broad
      # project_id index scan with a large heap fetch, which timed out on fork MR pages.
      projects = project || [source_project, target_project]
      # `triggered_by_merge_request` matches only parent MR pipelines; child
      # pipelines have a different source (`parent_pipeline`).
      pipelines_for_merge_request = Ci::Pipeline.triggered_by_merge_request(merge_request, projects)

      # Branch pipelines only ever belong to the source project, so skip that arm
      # (and the union) when scoping to the target project.
      return pipelines_for_merge_request unless include_source_branch?(project)

      pipelines_for_branch = triggered_for_branch.for_sha(recent_diff_head_shas(COMMITS_LIMIT))
      Ci::Pipeline.from_union([pipelines_for_merge_request, pipelines_for_branch])
    end

    # A nil project means both projects (which include the source); a single project
    # carries branch pipelines only when it is the source.
    def include_source_branch?(project)
      project.nil? || project == source_project
    end

    def triggered_for_branch
      source_project.all_pipelines.ci_branch_sources.for_branch(source_branch)
    end

    def sort(pipelines)
      pipelines.merge_request_event_first
    end

    def can_read_pipeline_in_target_project?
      strong_memoize(:can_read_pipeline_in_target_project) do
        Ability.allowed?(current_user, :read_pipeline, target_project)
      end
    end

    def can_read_pipeline_in_source_project?
      strong_memoize(:can_read_pipeline_in_source_project) do
        Ability.allowed?(current_user, :read_pipeline, source_project)
      end
    end
  end
end
