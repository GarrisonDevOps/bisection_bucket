# frozen_string_literal: true

module Ci
  class DownloadableArtifactEntity < Grape::Entity
    include RequestAwareEntity

    expose :artifacts do |pipeline, options|
      project = pipeline.project

      artifacts = Ability.filter_allowed(request.current_user, :read_job_artifacts, pipeline.downloadable_artifacts)

      BuildArtifactEntity.represent(artifacts, options.merge(project: project))
    end
  end
end
