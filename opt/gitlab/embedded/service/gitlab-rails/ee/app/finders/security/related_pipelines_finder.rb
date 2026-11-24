# frozen_string_literal: true

# Security::RelatedPipelinesFinder
#
# This finder returns the IDs of latest completed pipelines per given
# sources matching the SHA as the given pipeline. If the pipeline is a
# merged_request_pipeline, the source SHA of the pipeline is used to
# find the related pipelines.
#
# Arguments:
#   pipeline - pipeline for which the related pipelines should be returned
#   params:
#     sources:     Array<String>
#     ref:         String
#     merge_request: MergeRequest - excludes pipelines of other merge requests. Defaults
#                    to the merge request of the pipeline, so branch pipelines are not scoped.
module Security
  class RelatedPipelinesFinder
    attr_reader :pipeline, :params

    PIPELINES_LIMIT = 1_000
    # Cap the number of related pipelines aggregated by the MR security widget
    # to bound the number of findings queries and keep widget load times
    # predictable regardless of how many sibling pipelines ran for the same SHA.
    MAX_WIDGET_RELATED_PIPELINES = 10

    # Memoizes the related pipeline IDs for the duration of the request, so
    # multiple GraphQL fields resolving for the same pipeline (for example,
    # the security widget comparing several report types) trigger only one
    # lookup.
    def self.cached_ci_and_security_orchestration_pipeline_ids(pipeline)
      Gitlab::SafeRequestStore.fetch([:security_related_pipeline_ids, pipeline.id]) do
        new(pipeline, {
          sources: Enums::Ci::Pipeline.ci_and_security_orchestration_sources.values
        }).execute.first(MAX_WIDGET_RELATED_PIPELINES)
      end
    end

    def initialize(pipeline, params = {})
      @pipeline = pipeline
      @params = params
    end

    def execute
      pipelines = all_pipelines.no_tag
      pipelines = pipelines.for_branch(params[:ref]) if params[:ref].present?
      pipelines = pipelines.with_pipeline_source(params[:sources]) if params[:sources].present?
      pipelines = without_other_merge_requests(pipelines)
      pipelines = latest_completed_pipelines_matching_sha(pipelines)

      # Using map here as `pluck` would not work due to usage of `SELECT DISTINCT ON`
      pipeline_ids = pipelines.map(&:id)

      # rubocop:disable CodeReuse/ActiveRecord -- number of pipelines is limited by source
      Ci::Pipeline
        .object_hierarchy(all_pipelines.id_in(pipeline_ids), project_condition: :same)
        .base_and_descendant_ids.limit(PIPELINES_LIMIT).pluck(:id)
      # rubocop:enable CodeReuse/ActiveRecord
    end

    private

    delegate :project, to: :pipeline

    def all_pipelines
      project.all_pipelines
    end

    # Another merge request at the same sha would otherwise replace this merge
    # request's own pipeline as the latest of its source.
    def without_other_merge_requests(pipelines)
      merge_request_id = params[:merge_request]&.id || pipeline.merge_request_id
      return pipelines unless merge_request_id

      pipelines.without_other_merge_requests(merge_request_id)
    end

    def latest_completed_pipelines_matching_sha(pipelines)
      # merged_result_pipeline should include itself and the pipelines with source_sha
      sha = pipeline.merged_result_pipeline? ? [pipeline.source_sha, pipeline.sha] : pipeline.sha
      Ci::Pipeline.latest_limited_pipeline_ids_per_source(pipelines, sha)
    end
  end
end
