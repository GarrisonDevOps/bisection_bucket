# frozen_string_literal: true

require 'base64'

module EE
  module API
    module Geo
      extend ActiveSupport::Concern

      prepended do
        helpers do
          extend ::Gitlab::Utils::Override

          def sanitized_node_status_params
            # Exclude created_at and updated_at as these are managed by ActiveRecord
            # and may be nil if the sending node has an unsaved status object.
            valid_attributes = GeoNodeStatus.attribute_names - GeoNodeStatus::RESOURCE_STATUS_FIELDS - %w[id created_at updated_at]
            sanitized_params = params.slice(*valid_attributes)

            # sanitize status field
            sanitized_params['status'] = sanitized_params['status'].slice(*GeoNodeStatus::RESOURCE_STATUS_FIELDS) if sanitized_params['status']

            sanitized_params
          end

          # Check if a Geo request is legit or fail the flow
          #
          # @param [Hash] attributes to be matched against JWT
          def authorize_geo_transfer!(...)
            unauthorized! unless geo_jwt_decoder.valid_attributes?(...)
          end

          override :geo_proxy_response
          def geo_proxy_response
            # The methods used here (or their underlying methods) are cached
            # for:
            #
            # * 1 minute in memory
            # * 2 minutes in Redis
            #
            # The cached values are invalidated when changed.
            #
            non_proxy_response = super.merge({ geo_enabled: ::Gitlab::Geo.enabled? })

            return non_proxy_response unless ::Gitlab::Geo.secondary_with_primary?

            return non_proxy_response unless ::Gitlab::Geo.secondary_with_unified_url? ||
              ::Feature.enabled?(:geo_secondary_proxy_separate_urls, type: :ops)

            non_proxy_response.merge({
              geo_proxy_url: ::Gitlab::Geo.primary_node_internal_url,
              geo_proxy_extra_data: ::Gitlab::Geo.proxy_extra_data
            })
          end
        end

        resource :geo do
          desc 'Retrieve a replicable file' do
            detail 'Retrieves a replicable file for a Geo secondary site. Serves the file through a CDN or sendfile.'
            summary 'Internal endpoint that returns a replicable file'
            success code: 200
            failure [
              { code: 401, message: '401 Unauthorized' },
              { code: 404, message: '404 Not found' }
            ]
            tags %w[geo]
          end

          params do
            requires :replicable_name, type: String, desc: 'Name of the replicable type, for example `package_file`.', documentation: { example: 'package_file' }
            requires :replicable_id, type: Integer, desc: 'ID of the replicable.'
          end

          route_setting :authorization, skip_granular_token_authorization: :geo_jwt_auth
          get 'retrieve/:replicable_name/:replicable_id' do
            check_gitlab_geo_request_ip!
            params_sym = params.symbolize_keys
            authorize_geo_transfer!(**params_sym)

            decoded_params = geo_jwt_decoder.decode
            service = ::Geo::BlobUploadService.new(**params_sym, decoded_params: decoded_params)
            response = service.execute

            if response[:code] == :ok
              file = response[:file]
              present_carrierwave_file!(file)
            else
              error! response, response.delete(:code)
            end
          end

          desc 'List all pipeline refs for a project' do
            detail 'Lists all pipeline refs for a project. Secondary runners use them to check the site is up to date.'
            summary 'Used by secondary runners to verify the secondary instance has the very latest version'
            success code: 200, model: ::API::Entities::Geo::PipelineRefs
            is_array true
            failure [
              { code: 401, message: '401 Unauthorized' },
              { code: 404, message: '404 Not found' }
            ]
            tags %w[geo]
          end

          params do
            requires :gl_repository, type: String, desc: 'Repository to check.'
          end

          route_setting :authorization, skip_granular_token_authorization: :geo_jwt_auth
          get 'repositories/:gl_repository/pipeline_refs' do
            check_gitlab_geo_request_ip!
            authenticate_by_gitlab_geo_node_token!

            _, project, _ = ::Gitlab::GlRepository.parse(params[:gl_repository])

            present({ pipeline_refs: project.repository.list_refs(['refs/pipelines/']).collect(&:name) },
              with: ::API::Entities::Geo::PipelineRefs)
          end

          # Post current node information to primary (e.g. health, repos synced, repos failed, etc.)
          #
          # Example request:
          #   POST /geo/status
          desc 'Create a status for a secondary site' do
            detail 'Creates a status for a secondary Geo site on the primary site, including replication metrics.'
            summary 'Internal endpoint that posts the current node status'
            success code: 200, model: ::API::Entities::GeoNodeStatus
            failure [
              { code: 400, message: '400 Bad Request' },
              { code: 401, message: '401 Unauthorized' }
            ]
            tags %w[geo]
          end

          params do
            optional :data, type: Hash, desc: 'Object that contains status information and replication metrics for the Geo node.' do
              requires :geo_node_id, type: Integer, desc: 'ID of the Geo node the status applies to.'
              optional :db_replication_lag_seconds, type: Integer, desc: 'Database replication lag, in seconds.'
              optional :last_event_id, type: Integer, desc: 'ID of the last event.'
              optional :last_event_date, type: Time, desc: 'Last event date.'
              optional :cursor_last_event_id, type: Integer, desc: 'ID of the last event processed by the cursor.'
              optional :cursor_last_event_date, type: Time, desc: 'Date of the last event processed by the cursor.'
              optional :last_successful_status_check_at, type: Time, desc: 'Last successful status check date.'
              optional :status_message, type: String, desc: 'Status message.'
              optional :replication_slots_count, type: Integer, desc: 'Number of replication slots.'
              optional :replication_slots_used_count, type: Integer, desc: 'Number of replication slots in use.'
              optional :replication_slots_max_retained_wal_bytes, type: Integer, desc: 'Maximum number of bytes retained in the WAL on the primary.'
              optional :version, type: String, desc: 'GitLab version.'
              optional :revision, type: String, desc: 'GitLab revision.'
              optional :status, type: Hash, desc: 'Object that contains information on replication and verification status metrics for GitLab resources on Geo nodes.' do
                # GeoNodeStatus::RESOURCE_STATUS_FIELDS
                optional :projects_count, type: Integer, desc: 'Number of projects.'
                optional :container_repositories_replication_enabled, type: Grape::API::Boolean, desc: 'If `true`, container repository replication is enabled.'
                optional :lfs_objects_count, type: Integer, desc: 'Number of LFS objects.'
                optional :lfs_objects_checksum_total_count, type: Integer, desc: 'Number of LFS objects available to checksum on the primary site.'
                optional :lfs_objects_checksummed_count, type: Integer, desc: 'Number of LFS objects that have been checksummed.'
                optional :lfs_objects_checksum_failed_count, type: Integer, desc: 'Number of LFS objects for which checksum calculation failed.'
                optional :lfs_objects_synced_count, type: Integer, desc: 'Number of LFS objects synced.'
                optional :lfs_objects_failed_count, type: Integer, desc: 'Number of LFS objects that failed to sync.'
                optional :lfs_objects_registry_count, type: Integer, desc: 'Number of LFS objects tracked in the registry.'
                optional :lfs_objects_verification_total_count, type: Integer, desc: 'Number of LFS objects available to verify on the secondary site.'
                optional :lfs_objects_verified_count, type: Integer, desc: 'Number of LFS objects verified.'
                optional :lfs_objects_verification_failed_count, type: Integer, desc: 'Number of LFS objects for which verification failed.'
                optional :merge_request_diffs_count, type: Integer, desc: 'Number of merge request diffs.'
                optional :merge_request_diffs_checksum_total_count, type: Integer, desc: 'Number of merge request diffs available to checksum on the primary site.'
                optional :merge_request_diffs_checksummed_count, type: Integer, desc: 'Number of merge request diffs that have been checksummed.'
                optional :merge_request_diffs_checksum_failed_count, type: Integer, desc: 'Number of merge request diffs for which checksum calculation failed.'
                optional :merge_request_diffs_synced_count, type: Integer, desc: 'Number of merge request diffs synced.'
                optional :merge_request_diffs_failed_count, type: Integer, desc: 'Number of merge request diffs that failed to sync.'
                optional :merge_request_diffs_registry_count, type: Integer, desc: 'Number of merge request diffs tracked in the registry.'
                optional :merge_request_diffs_verification_total_count, type: Integer, desc: 'Number of merge request diffs available to verify on the secondary site.'
                optional :merge_request_diffs_verified_count, type: Integer, desc: 'Number of merge request diffs verified.'
                optional :merge_request_diffs_verification_failed_count, type: Integer, desc: 'Number of merge request diffs for which verification failed.'
                optional :package_files_count, type: Integer, desc: 'Number of package files.'
                optional :package_files_checksum_total_count, type: Integer, desc: 'Number of package files available to checksum on the primary site.'
                optional :package_files_checksummed_count, type: Integer, desc: 'Number of package files that have been checksummed.'
                optional :package_files_checksum_failed_count, type: Integer, desc: 'Number of package files for which checksum calculation failed.'
                optional :package_files_synced_count, type: Integer, desc: 'Number of package files synced.'
                optional :package_files_failed_count, type: Integer, desc: 'Number of package files that failed to sync.'
                optional :package_files_registry_count, type: Integer, desc: 'Number of package files tracked in the registry.'
                optional :package_files_verification_total_count, type: Integer, desc: 'Number of package files available to verify on the secondary site.'
                optional :package_files_verified_count, type: Integer, desc: 'Number of package files verified.'
                optional :package_files_verification_failed_count, type: Integer, desc: 'Number of package files for which verification failed.'
                optional :packages_nuget_symbols_count, type: Integer, desc: 'Number of NuGet symbols.'
                optional :packages_nuget_symbols_checksum_total_count, type: Integer, desc: 'Number of NuGet symbols available to checksum on the primary site.'
                optional :packages_nuget_symbols_checksummed_count, type: Integer, desc: 'Number of NuGet symbols that have been checksummed.'
                optional :packages_nuget_symbols_checksum_failed_count, type: Integer, desc: 'Number of NuGet symbols for which checksum calculation failed.'
                optional :packages_nuget_symbols_synced_count, type: Integer, desc: 'Number of NuGet symbols synced.'
                optional :packages_nuget_symbols_failed_count, type: Integer, desc: 'Number of NuGet symbols that failed to sync.'
                optional :packages_nuget_symbols_registry_count, type: Integer, desc: 'Number of NuGet symbols tracked in the registry.'
                optional :packages_nuget_symbols_verification_total_count, type: Integer, desc: 'Number of NuGet symbols available to verify on the secondary site.'
                optional :packages_nuget_symbols_verified_count, type: Integer, desc: 'Number of NuGet symbols verified.'
                optional :packages_nuget_symbols_verification_failed_count, type: Integer, desc: 'Number of NuGet symbols for which verification failed.'
                optional :terraform_state_versions_count, type: Integer, desc: 'Number of Terraform state versions.'
                optional :terraform_state_versions_checksum_total_count, type: Integer, desc: 'Number of Terraform state versions available to checksum on the primary site.'
                optional :terraform_state_versions_checksummed_count, type: Integer, desc: 'Number of Terraform state versions that have been checksummed.'
                optional :terraform_state_versions_checksum_failed_count, type: Integer, desc: 'Number of Terraform state versions for which checksum calculation failed.'
                optional :terraform_state_versions_synced_count, type: Integer, desc: 'Number of Terraform state versions synced.'
                optional :terraform_state_versions_failed_count, type: Integer, desc: 'Number of Terraform state versions that failed to sync.'
                optional :terraform_state_versions_registry_count, type: Integer, desc: 'Number of Terraform state versions tracked in the registry.'
                optional :terraform_state_versions_verification_total_count, type: Integer, desc: 'Number of Terraform state versions available to verify on the secondary site.'
                optional :terraform_state_versions_verified_count, type: Integer, desc: 'Number of Terraform state versions verified.'
                optional :terraform_state_versions_verification_failed_count, type: Integer, desc: 'Number of Terraform state versions for which verification failed.'
                optional :snippet_repositories_count, type: Integer, desc: 'Number of snippet repositories.'
                optional :snippet_repositories_checksum_total_count, type: Integer, desc: 'Number of snippet repositories available to checksum on the primary site.'
                optional :snippet_repositories_checksummed_count, type: Integer, desc: 'Number of snippet repositories that have been checksummed.'
                optional :snippet_repositories_checksum_failed_count, type: Integer, desc: 'Number of snippet repositories for which checksum calculation failed.'
                optional :snippet_repositories_synced_count, type: Integer, desc: 'Number of snippet repositories synced.'
                optional :snippet_repositories_failed_count, type: Integer, desc: 'Number of snippet repositories that failed to sync.'
                optional :snippet_repositories_registry_count, type: Integer, desc: 'Number of snippet repositories tracked in the registry.'
                optional :snippet_repositories_verification_total_count, type: Integer, desc: 'Number of snippet repositories available to verify on the secondary site.'
                optional :snippet_repositories_verified_count, type: Integer, desc: 'Number of snippet repositories verified.'
                optional :snippet_repositories_verification_failed_count, type: Integer, desc: 'Number of snippet repositories for which verification failed.'
                optional :group_wiki_repositories_count, type: Integer, desc: 'Number of group wiki repositories.'
                optional :group_wiki_repositories_checksum_total_count, type: Integer, desc: 'Number of group wiki repositories available to checksum on the primary site.'
                optional :group_wiki_repositories_checksummed_count, type: Integer, desc: 'Number of group wiki repositories that have been checksummed.'
                optional :group_wiki_repositories_checksum_failed_count, type: Integer, desc: 'Number of group wiki repositories for which checksum calculation failed.'
                optional :group_wiki_repositories_synced_count, type: Integer, desc: 'Number of group wiki repositories synced.'
                optional :group_wiki_repositories_failed_count, type: Integer, desc: 'Number of group wiki repositories that failed to sync.'
                optional :group_wiki_repositories_registry_count, type: Integer, desc: 'Number of group wiki repositories tracked in the registry.'
                optional :group_wiki_repositories_verification_total_count, type: Integer, desc: 'Number of group wiki repositories available to verify on the secondary site.'
                optional :group_wiki_repositories_verified_count, type: Integer, desc: 'Number of group wiki repositories verified.'
                optional :group_wiki_repositories_verification_failed_count, type: Integer, desc: 'Number of group wiki repositories for which verification failed.'
                optional :pipeline_artifacts_count, type: Integer, desc: 'Number of pipeline artifacts.'
                optional :pipeline_artifacts_checksum_total_count, type: Integer, desc: 'Number of pipeline artifacts available to checksum on the primary site.'
                optional :pipeline_artifacts_checksummed_count, type: Integer, desc: 'Number of pipeline artifacts that have been checksummed.'
                optional :pipeline_artifacts_checksum_failed_count, type: Integer, desc: 'Number of pipeline artifacts for which checksum calculation failed.'
                optional :pipeline_artifacts_synced_count, type: Integer, desc: 'Number of pipeline artifacts synced.'
                optional :pipeline_artifacts_failed_count, type: Integer, desc: 'Number of pipeline artifacts that failed to sync.'
                optional :pipeline_artifacts_registry_count, type: Integer, desc: 'Number of pipeline artifacts tracked in the registry.'
                optional :pipeline_artifacts_verification_total_count, type: Integer, desc: 'Number of pipeline artifacts available to verify on the secondary site.'
                optional :pipeline_artifacts_verified_count, type: Integer, desc: 'Number of pipeline artifacts verified.'
                optional :pipeline_artifacts_verification_failed_count, type: Integer, desc: 'Number of pipeline artifacts for which verification failed.'
                optional :pages_deployments_count, type: Integer, desc: 'Number of Pages deployments.'
                optional :pages_deployments_checksum_total_count, type: Integer, desc: 'Number of Pages deployments available to checksum on the primary site.'
                optional :pages_deployments_checksummed_count, type: Integer, desc: 'Number of Pages deployments that have been checksummed.'
                optional :pages_deployments_checksum_failed_count, type: Integer, desc: 'Number of Pages deployments for which checksum calculation failed.'
                optional :pages_deployments_synced_count, type: Integer, desc: 'Number of Pages deployments synced.'
                optional :pages_deployments_failed_count, type: Integer, desc: 'Number of Pages deployments that failed to sync.'
                optional :pages_deployments_registry_count, type: Integer, desc: 'Number of Pages deployments tracked in the registry.'
                optional :pages_deployments_verification_total_count, type: Integer, desc: 'Number of Pages deployments available to verify on the secondary site.'
                optional :pages_deployments_verified_count, type: Integer, desc: 'Number of Pages deployments verified.'
                optional :pages_deployments_verification_failed_count, type: Integer, desc: 'Number of Pages deployments for which verification failed.'
                optional :uploads_count, type: Integer, desc: 'Number of uploads.'
                optional :uploads_checksum_total_count, type: Integer, desc: 'Number of uploads available to checksum on the primary site.'
                optional :uploads_checksummed_count, type: Integer, desc: 'Number of uploads that have been checksummed.'
                optional :uploads_checksum_failed_count, type: Integer, desc: 'Number of uploads for which checksum calculation failed.'
                optional :uploads_synced_count, type: Integer, desc: 'Number of uploads synced.'
                optional :uploads_failed_count, type: Integer, desc: 'Number of uploads that failed to sync.'
                optional :uploads_registry_count, type: Integer, desc: 'Number of uploads tracked in the registry.'
                optional :uploads_verification_total_count, type: Integer, desc: 'Number of uploads available to verify on the secondary site.'
                optional :uploads_verified_count, type: Integer, desc: 'Number of uploads verified.'
                optional :uploads_verification_failed_count, type: Integer, desc: 'Number of uploads for which verification failed.'
                optional :job_artifacts_count, type: Integer, desc: 'Number of job artifacts.'
                optional :job_artifacts_checksum_total_count, type: Integer, desc: 'Number of job artifacts available to checksum on the primary site.'
                optional :job_artifacts_checksummed_count, type: Integer, desc: 'Number of job artifacts that have been checksummed.'
                optional :job_artifacts_checksum_failed_count, type: Integer, desc: 'Number of job artifacts for which checksum calculation failed.'
                optional :job_artifacts_synced_count, type: Integer, desc: 'Number of job artifacts synced.'
                optional :job_artifacts_failed_count, type: Integer, desc: 'Number of job artifacts that failed to sync.'
                optional :job_artifacts_registry_count, type: Integer, desc: 'Number of job artifacts tracked in the registry.'
                optional :job_artifacts_verification_total_count, type: Integer, desc: 'Number of job artifacts available to verify on the secondary site.'
                optional :job_artifacts_verified_count, type: Integer, desc: 'Number of job artifacts verified.'
                optional :job_artifacts_verification_failed_count, type: Integer, desc: 'Number of job artifacts for which verification failed.'
                optional :ci_secure_files_count, type: Integer, desc: 'Number of CI/CD secure files.'
                optional :ci_secure_files_checksum_total_count, type: Integer, desc: 'Number of CI/CD secure files available to checksum on the primary site.'
                optional :ci_secure_files_checksummed_count, type: Integer, desc: 'Number of CI/CD secure files that have been checksummed.'
                optional :ci_secure_files_checksum_failed_count, type: Integer, desc: 'Number of CI/CD secure files for which checksum calculation failed.'
                optional :ci_secure_files_synced_count, type: Integer, desc: 'Number of CI/CD secure files synced.'
                optional :ci_secure_files_failed_count, type: Integer, desc: 'Number of CI/CD secure files that failed to sync.'
                optional :ci_secure_files_registry_count, type: Integer, desc: 'Number of CI/CD secure files tracked in the registry.'
                optional :ci_secure_files_verification_total_count, type: Integer, desc: 'Number of CI/CD secure files available to verify on the secondary site.'
                optional :ci_secure_files_verified_count, type: Integer, desc: 'Number of CI/CD secure files verified.'
                optional :ci_secure_files_verification_failed_count, type: Integer, desc: 'Number of CI/CD secure files for which verification failed.'
                optional :container_repositories_count, type: Integer, desc: 'Number of container repositories.'
                optional :container_repositories_checksum_total_count, type: Integer, desc: 'Number of container repositories available to checksum on the primary site.'
                optional :container_repositories_checksummed_count, type: Integer, desc: 'Number of container repositories that have been checksummed.'
                optional :container_repositories_checksum_failed_count, type: Integer, desc: 'Number of container repositories for which checksum calculation failed.'
                optional :container_repositories_synced_count, type: Integer, desc: 'Number of container repositories synced.'
                optional :container_repositories_failed_count, type: Integer, desc: 'Number of container repositories that failed to sync.'
                optional :container_repositories_registry_count, type: Integer, desc: 'Number of container repositories tracked in the registry.'
                optional :container_repositories_verification_total_count, type: Integer, desc: 'Number of container repositories available to verify on the secondary site.'
                optional :container_repositories_verified_count, type: Integer, desc: 'Number of container repositories verified.'
                optional :container_repositories_verification_failed_count, type: Integer, desc: 'Number of container repositories for which verification failed.'
                optional :git_fetch_event_count_weekly, type: Integer, desc: 'Number of Git fetch events in the past week.'
                optional :git_push_event_count_weekly, type: Integer, desc: 'Number of Git push events in the past week.'
                optional :proxy_remote_requests_event_count_weekly, type: Integer, desc: 'Number of remote requests proxied in the past week.'
                optional :proxy_local_requests_event_count_weekly, type: Integer, desc: 'Number of HTTP requests received by the secondary site in the past week.'
              end
            end
          end

          route_setting :authorization, skip_granular_token_authorization: :geo_jwt_auth
          post 'status' do
            check_gitlab_geo_request_ip!
            authenticate_by_gitlab_geo_node_token!

            db_status = GeoNode.find(params[:geo_node_id]).find_or_build_status

            unless db_status.update(sanitized_node_status_params.merge(last_successful_status_check_at: Time.now.utc))
              render_validation_error!(db_status)
            end
          end

          # Secondaries report resources that persistently fail verification so
          # the primary can act on them (for example, re-verify its own
          # checksum for a resource stuck in a checksum mismatch).
          #
          # The path and param shape are intentionally generic (not specific to
          # any one error type) since REST API v4 endpoints are expensive to
          # change once shipped: `error_type` discriminates what a given entry
          # means, and `context` carries error-type-specific extra data.
          desc 'Create a report of persistent verification failures' do
            detail 'Creates a report on the primary site of resources that persistently fail verification on a secondary site.'
            summary 'Internal endpoint that reports persistent verification failures to the primary'
            success code: 202
            failure [
              { code: 401, message: '401 Unauthorized' },
              { code: 404, message: '404 Not found' },
              { code: 400, message: '400 Bad request' }
            ]
            tags %w[geo]
          end

          params do
            requires :geo_node_id, type: Integer, desc: 'The Geo node ID of the reporting secondary'
            requires :failures, type: Array, desc: 'Persistent verification failures reported by the secondary' do
              requires :error_type, type: String, desc: 'The type of verification error being reported',
                documentation: { example: 'checksum_mismatch' }
              requires :replicable_name, type: String, desc: 'The replicable name of a replicator instance',
                documentation: { example: 'upload' }
              requires :replicable_id, type: Integer, desc: 'The model record ID'
              requires :verification_retry_count, type: Integer, desc: 'The number of consecutive verification failures'
              optional :context, type: Hash, desc: 'Additional error-type-specific data'
            end
          end

          route_setting :authorization, skip_granular_token_authorization: :geo_jwt_auth
          post 'failures' do
            check_gitlab_geo_request_ip!
            authenticate_by_gitlab_geo_node_token!

            not_found! unless ::Gitlab::Geo.primary?
            not_found! unless ::Feature.enabled?(:geo_self_heal_checksum_mismatch, :instance, type: :ops)
            bad_request!('Too many failures') if params[:failures].size > ::Geo::VerificationFailureReportWorker::MAX_FAILURES_PER_REQUEST

            ::Geo::VerificationFailureReportWorker.perform_async(params[:geo_node_id], params[:failures].map(&:to_h))

            status 202
          end

          # git over SSH secondary endpoints -> primary related proxying logic
          #
          resource 'proxy_git_ssh' do
            format :json

            # For git clone/pull

            desc 'Proxy a git-upload-pack info/refs request to the primary site' do
              detail 'Proxies a git-upload-pack info/refs request from a secondary site to the primary site.'
              summary 'Internal endpoint that returns info refs upload pack for clone or pull operations'
              success code: 200
              failure [{ code: 401, message: '401 Unauthorized' }]
              tags %w[geo]
            end

            params do
              requires :secret_token, type: String, desc: 'Secret token used to authenticate requests from GitLab Shell.'
              requires :data, type: Hash, desc: 'Object that contains the payload data for the Geo operation.' do
                requires :gl_id, type: String, desc: 'ID of the user performing the operation.'
                requires :primary_repo, type: String, desc: 'Primary repository to clone or pull from.'
              end
            end

            route_setting :authorization, skip_granular_token_authorization: :gitlab_shell_token_auth
            post 'info_refs_upload_pack' do
              authenticate_by_gitlab_shell_token!
              params.delete(:secret_token)

              response = ::Gitlab::Geo::GitSSHProxy.new(params['data']).info_refs_upload_pack

              status(response.code)
              response.body
            end

            desc 'Proxy a git-upload-pack request to the primary site' do
              detail 'Proxies a git-upload-pack request from a secondary site to the primary site.'
              summary 'Internal endpoint that posts git-upload-pack for clone or pull operations'
              success code: 200
              failure [{ code: 401, message: '401 Unauthorized' }]
              tags %w[geo]
            end

            params do
              requires :secret_token, type: String, desc: 'Secret token used to authenticate requests from GitLab Shell to Geo proxy endpoints.'
              requires :data, type: Hash, desc: 'Object that contains the payload data for the Geo operation.' do
                requires :gl_id, type: String, desc: 'ID of the user performing the operation.'
                requires :primary_repo, type: String, desc: 'Primary repository to clone or pull from.'
              end
              requires :output, type: String, desc: 'Output from `git-upload-pack`.'
            end

            route_setting :authorization, skip_granular_token_authorization: :gitlab_shell_token_auth
            post 'upload_pack' do
              authenticate_by_gitlab_shell_token!
              params.delete(:secret_token)

              response = ::Gitlab::Geo::GitSSHProxy.new(params['data']).upload_pack(params['output'])

              status(response.code)
              response.body
            end

            # For git push

            desc 'Proxy a git-receive-pack info/refs request to the primary site' do
              detail 'Proxies a git-receive-pack info/refs request from a secondary site to the primary site.'
              summary 'Internal endpoint that returns git-received-pack output for git push'
              success code: 200
              failure [{ code: 401, message: '401 Unauthorized' }]
              tags %w[geo]
            end

            params do
              requires :secret_token, type: String, desc: 'Secret token used to authenticate requests from GitLab Shell to Geo proxy endpoints.'
              requires :data, type: Hash, desc: 'Object that contains the payload data for the Geo operation.' do
                requires :gl_id, type: String, desc: 'ID of the user performing the operation.'
                requires :primary_repo, type: String, desc: 'Primary repository to push to.'
              end
            end

            route_setting :authorization, skip_granular_token_authorization: :gitlab_shell_token_auth
            post 'info_refs_receive_pack' do
              authenticate_by_gitlab_shell_token!
              params.delete(:secret_token)

              response = ::Gitlab::Geo::GitSSHProxy.new(params['data']).info_refs_receive_pack
              status(response.code)
              response.body
            end

            desc 'Proxy a git-receive-pack request to the primary site' do
              detail 'Proxies a git-receive-pack request from a secondary site to the primary site.'
              summary 'Internal endpoint that posts git-receive-pack for git push'
              success code: 200
              failure [{ code: 401, message: '401 Unauthorized' }]
              tags %w[geo]
            end

            params do
              requires :secret_token, type: String, desc: 'Secret token used to authenticate requests from GitLab Shell to Geo proxy endpoints.'
              requires :data, type: Hash, desc: 'Object that contains the payload data for the Geo operation.' do
                requires :gl_id, type: String, desc: 'ID of the user performing the operation.'
                requires :primary_repo, type: String, desc: 'Primary repository to push to.'
              end
              requires :output, type: String, desc: 'Output from `git-receive-pack`.'
            end

            route_setting :authorization, skip_granular_token_authorization: :gitlab_shell_token_auth
            post 'receive_pack' do
              authenticate_by_gitlab_shell_token!
              params.delete(:secret_token)

              response = ::Gitlab::Geo::GitSSHProxy.new(params['data']).receive_pack(params['output'])
              status(response.code)
              response.body
            end
          end

          resource 'node_proxy' do
            before do
              authenticated_as_admin!
            end

            route_param :id, type: Integer, desc: 'The ID of the Geo node' do
              helpers do
                def geo_node
                  strong_memoize(:geo_node) { GeoNode.find(params[:id]) }
                end
              end

              desc 'Query the GraphQL endpoint of an existing Geo site' do
                detail 'Queries the GraphQL endpoint of an existing Geo site.'
                summary 'Query the GraphQL endpoint of an existing Geo node'
                success code: 200
                failure [
                  { code: 404, message: '404 GeoNode Not Found' },
                  { code: 500, message: '500 Internal Server Error' }
                ]
                tags %w[geo]
              end

              # Example request:
              #   POST /geo/node_proxy/:id/graphql
              route_setting :tier, :premium
              route_setting :authorization, permissions: :read_geo_node, boundary_type: :instance,
                assignable_when: [:admin]
              post 'graphql' do
                not_found!('GeoNode') unless geo_node

                response = ::Geo::GraphqlRequestService.new(geo_node, current_user).execute(env['api.request.input'])
                error!({ error: 'An error occurred while processing the GraphQL request to the Geo node' }, 500) unless response

                status 200
                response
              end
            end
          end
        end
      end
    end
  end
end
