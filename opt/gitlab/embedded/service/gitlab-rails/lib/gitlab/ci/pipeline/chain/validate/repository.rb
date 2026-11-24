# frozen_string_literal: true

module Gitlab
  module Ci
    module Pipeline
      module Chain
        module Validate
          class Repository < Chain::Base
            include Chain::Helpers

            REFERENCE_NOT_FOUND_MESSAGE = 'Reference not found'
            COMMIT_NOT_FOUND_MESSAGE = 'Commit not found'

            def perform!
              if @command.ambiguous_ref?
                return error('Ref is ambiguous')
              end

              unless @command.ref_exists?
                return error(REFERENCE_NOT_FOUND_MESSAGE)
              end

              unless @command.sha
                return error(COMMIT_NOT_FOUND_MESSAGE)
              end

              cache_tag_message if @command.tag?
            rescue Gitlab::Git::ResourceExhaustedError => e
              # Gitaly is overloaded (for example, concurrency/queue limits or an open circuit breaker).
              # Surface a dedicated, non-persistable failure reason so the transient condition is
              # observable via the gitlab_ci_pipeline_failure_reasons metric instead of an unknown failure.
              error(e.message, failure_reason: :gitaly_unavailable)
            end

            def break?
              @pipeline.errors.any?
            end

            private

            def cache_tag_message
              project.repository.cached_tag_message(@command.ref)
            rescue Gitlab::Git::BaseError => e
              Gitlab::ErrorTracking.track_exception(e, project_id: project.id)
            end
          end
        end
      end
    end
  end
end
