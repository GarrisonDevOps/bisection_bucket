# frozen_string_literal: true

module EE
  module API
    module Releases
      extend ActiveSupport::Concern

      prepended do
        resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          desc 'Generate release evidence' do
            detail 'Generates an evidence for an existing release. Requests are rate limited per user ' \
              '(`release_evidence_collections_limit_per_user` application setting). Requests over the limit are ' \
              'blocked when the `rate_limit_release_evidence_collections_per_user` feature flag is enabled, and ' \
              'only logged otherwise. When the `release_evidence_size_limit` feature flag is enabled, returns ' \
              '`422` if the evidence would exceed the `release_evidence_max_size_bytes` application setting.'
            success ::API::Entities::Release
            failure [
              { code: 401, message: 'Unauthorized' },
              { code: 404, message: 'Not found' },
              { code: 422, message: 'Unprocessable entity' },
              { code: 429, message: 'Too many requests' }
            ]
            tags %w[releases]
          end
          params do
            requires :tag_name, type: String, desc: 'Git tag the release is associated with.', as: :tag
          end
          route_setting :authentication, job_token_allowed: true
          route_setting :authorization, job_token_policies: :admin_releases, permissions: :create_release_evidence,
            boundary_type: :project
          post ':id/releases/:tag_name/evidence', requirements: ::API::Releases::RELEASE_ENDPOINT_REQUIREMENTS do
            authorize_create_evidence!
            check_rate_limit!(:release_evidence_collections_per_user, scope: { user: current_user })

            if release.present?
              size_limit = ::Releases::EvidenceSizeLimit.new(release)
              unprocessable_entity!(size_limit.error_message) if size_limit.exceeded?

              if ::Feature.enabled?(:release_evidence_bounded_pipeline_lookup, release.project)
                # The worker never finds a pipeline passed as an object, so we skip the lookup and collect without one
                ::Releases::CreateEvidenceWorker.perform_async(release.id)
              else
                params = { tag: release.tag }
                evidence_pipeline = ::Releases::EvidencePipelineFinder.new(release.project, params).execute
                ::Releases::CreateEvidenceWorker.perform_async(release.id, evidence_pipeline)
              end

              status :accepted
            else
              status :not_found
            end
          end
        end

        helpers do
          extend ::Gitlab::Utils::Override

          override :authorize_create_evidence!
          def authorize_create_evidence!
            authorize_create_release!
          end
        end
      end
    end
  end
end
