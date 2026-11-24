# frozen_string_literal: true

module Ci
  class ArtifactDownloadAuditor
    NAME = 'job_artifact_downloaded'
    UNKNOWN_FILENAME = 'unknown'
    NEVER = 'never'

    attr_reader :current_user, :build

    def initialize(build:, filename:, artifact: nil, current_user: nil)
      @current_user = current_user
      @build = build
      @filename = filename
      @artifact = artifact
    end

    def execute
      return unless job_artifact

      ::Gitlab::Audit::Auditor.audit(
        name: NAME,
        author: author,
        scope: build.project,
        target: target,
        message: message,
        additional_details: {
          expire_at: expiry,
          filename: filename,
          artifact_id: job_artifact.id,
          artifact_type: job_artifact.class.name
        }
      )
    end

    private

    def author
      return Gitlab::Audit::UnauthenticatedAuthor.new if current_user.nil?

      current_user
    end

    def filename
      @filename.presence || UNKNOWN_FILENAME
    end

    def message
      "Downloaded artifact #{filename} (expiration: #{expiry})"
    end

    def job_artifact
      @artifact || build.job_artifacts_archive
    end

    def expiry
      expire_at = job_artifact&.expire_at.presence

      return NEVER unless expire_at

      expire_at.iso8601
    end

    def target
      build.pipeline || build
    end
  end
end
