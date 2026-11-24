# frozen_string_literal: true

module EE
  module API
    module Ci
      module JobArtifacts
        extend ActiveSupport::Concern

        prepended do
          helpers do
            def audit_download(build, filename, artifact: nil)
              super

              ::Ci::ArtifactDownloadAuditor.new(
                current_user: current_user,
                build: build,
                artifact: artifact,
                filename: filename
              ).execute
            end

            def authorize_download_artifacts!
              super

              check_cross_project_pipelines_feature!
            end

            def check_cross_project_pipelines_feature!
              if job_token_authentication? && !user_project.licensed_feature_available?(:cross_project_pipelines)
                not_found!('Project')
              end
            end
          end
        end
      end
    end
  end
end
