# frozen_string_literal: true

module Releases
  class EvidencePipelineFinder
    include Gitlab::Utils::StrongMemoize

    attr_reader :project, :params

    def initialize(project, params = {})
      @project = project
      @params = params
    end

    def execute
      # TODO: remove this with the release creation moved to it's own form https://gitlab.com/gitlab-org/gitlab/-/issues/214245
      return params[:evidence_pipeline] if params[:evidence_pipeline]

      sha = existing_tag&.dereferenced_target&.sha
      sha ||= repository&.commit(ref)&.sha

      return unless sha

      # Building the relation reads the project's features from main, which the read-only block below rejects
      pipelines = project.ci_pipelines.for_sha(sha)

      return pipelines.last unless Feature.enabled?(:release_evidence_bounded_pipeline_lookup, project)

      last_pipeline_with_fast_read_timeout(pipelines)
    end

    private

    # A commit with many pipelines can make this lookup slow, and the evidence is still collected without one
    def last_pipeline_with_fast_read_timeout(pipelines)
      ::Ci::ApplicationRecord.with_fast_read_statement_timeout { pipelines.last } # rubocop:disable Performance/ActiveRecordSubtransactionMethods -- this is called outside a transaction
    rescue ActiveRecord::QueryCanceled => e # rubocop:disable Database/RescueQueryCanceled -- used with fast_read_statement_timeout so a slow lookup doesn't block evidence collection
      Gitlab::ErrorTracking.log_exception(e, Labkit::Fields::GL_PROJECT_ID => project.id)
      nil
    end

    def repository
      strong_memoize(:repository) do
        project.repository
      end
    end

    def existing_tag
      repository.find_tag(tag_name)
    end

    def tag_name
      params[:tag]
    end

    def ref
      params[:ref]
    end
  end
end
