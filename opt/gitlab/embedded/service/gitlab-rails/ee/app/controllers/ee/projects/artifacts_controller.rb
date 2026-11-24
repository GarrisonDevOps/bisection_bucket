# frozen_string_literal: true

module EE
  module Projects
    module ArtifactsController
      extend ::Gitlab::Utils::Override

      private

      override :audit_download
      def audit_download(build, filename)
        super

        ::Ci::ArtifactDownloadAuditor.new(
          current_user: current_user,
          build: build,
          artifact: job_artifact,
          filename: filename
        ).execute
      end
    end
  end
end
