# frozen_string_literal: true

module API
  module Internal
    class Orbit < ::API::Base
      include APIGuard
      include PaginationParams

      rescue_from Gitlab::Git::InvalidPageToken do |error|
        error!({ message: error.message }, 400)
      end

      API_HEADER = 'Gitlab-Orbit-Api-Request'
      MAX_LIST_BLOBS_REVISIONS = 5000
      # Caps base/target pairs per POST changed_paths call. Gitaly's FindChangedPaths
      # has no limit of its own, so this is the only bound on one request's work.
      MAX_CHANGED_PATHS_COMPARISONS = 1000
      BLOB_BYTES_LIMIT = 1_048_576
      # Fixed service name for authenticated Orbit indexer traffic, used as the
      # Gitaly client_name and Rails client_service, and to select the Orbit audit
      # author. Intentionally independent of the JWT subject prefix, which stays
      # `gkg-indexer:` for compatibility.
      ORBIT_CLIENT_NAME = 'orbit-indexer'

      helpers do
        def authenticate_knowledge_graph_request!
          token = request.headers[API_HEADER]

          decoded = token.present? &&
            ::Analytics::KnowledgeGraph::JwtAuth.decode_token(token, expected_sub_prefix: 'gkg-indexer:')

          render_api_error!('Knowledge Graph JWT authentication invalid', :unauthorized) unless decoded
        end

        def find_merge_request_diff_or_not_found!(project)
          diff_record = ::MergeRequestDiff.find_by(id: params[:diff_id], project_id: project.id) # rubocop:disable CodeReuse/ActiveRecord -- scoped lookup by composite key not suitable for a finder class
          not_found!('merge_request_diff') unless diff_record

          diff_record
        end

        def find_project_or_not_found!
          project = find_project(params[:project_id])
          not_found! unless project

          project
        end

        def normalize_repository_pagination!
          bad_request!('per_page must be positive') unless params[:per_page].to_i > 0

          params[:per_page] = [params[:per_page], Gitlab::PaginationDelegate::MAX_PER_PAGE].min
        end

        def audit_cloud_connector_token_issued
          ::Gitlab::Audit::Auditor.audit(
            name: 'orbit_cloud_connector_token_issued',
            author: ::Gitlab::Audit::OrbitIndexerAuthor.new,
            scope: ::Gitlab::Audit::InstanceScope.new,
            target: ::Gitlab::Audit::InstanceScope.new,
            ip_address: ip_address,
            message: 'Cloud Connector token issued to Orbit'
          )
        end

        def validate_fast_forward!(repository, left_revision, right_revision)
          return if Gitlab::Git.blank_ref?(left_revision) || left_revision == repository.empty_tree_id
          return if repository.ancestor?(left_revision, right_revision)

          bad_request!("left_tree_revision is not an ancestor of right_tree_revision (force push detected)")
        end
      end

      namespace 'internal' do
        namespace 'orbit' do
          desc 'Fetch the Cloud Connector token' do
            detail 'Returns the instance Cloud Connector token so the Orbit indexer can ' \
              'authenticate billing-event emission on Self-Managed and Dedicated instances. ' \
              'The token carries its own exp claim; callers that need the expiry decode it ' \
              'from the token rather than relying on a separate field.'
            tags 'orbit'
            success code: 200
          end
          route_setting :authorization, skip_granular_token_authorization: :orbit_internal_auth
          get 'cloud_connector_token', feature_category: :knowledge_graph, urgency: :low do
            verify_workhorse_api!
            authenticate_knowledge_graph_request!

            token = ::CloudConnector::Tokens.cloud_connector_token
            service_unavailable!('Cloud Connector token is not available') if token.blank?

            unless ::CloudConnector::Tokens.well_formed_cloud_connector_token?(token)
              service_unavailable!('Cloud Connector token is malformed')
            end

            audit_cloud_connector_token_issued

            { token: token }
          end

          desc 'Get the instance identity and settings' do
            detail 'Returns what Orbit needs to know about this instance, grouped by topic. ' \
              'New fields are only added, so older Orbit versions keep working.'
            tags 'orbit'
            success code: 200
          end
          route_setting :authorization, skip_granular_token_authorization: :orbit_internal_auth
          get 'instance', feature_category: :knowledge_graph, urgency: :low do
            verify_workhorse_api!
            authenticate_knowledge_graph_request!

            {
              identity: ::Analytics::KnowledgeGraph::JwtAuth.instance_identity,
              settings: {
                product_usage_data_enabled: ::Gitlab::Usage::ProductUsageDataSetting.enabled? || false
              }
            }
          end

          namespace 'project' do
            before do
              verify_workhorse_api!
              authenticate_knowledge_graph_request!
              ::Gitlab::ApplicationContext.push(client_service: ORBIT_CLIENT_NAME)
            end

            route_param :project_id, type: String, desc: 'The ID or path of the project' do
              desc 'Get project info' do
                detail 'Returns the default branch, its head SHA, and the repository storage for the given project'
                tags 'orbit'
                success code: 200
              end
              route_setting :authorization, skip_granular_token_authorization: :orbit_internal_auth
              get '/info', feature_category: :knowledge_graph, urgency: :low do
                project = find_project_or_not_found!
                default_branch = project.default_branch_or_main
                default_branch_ref = Gitlab::Git::BRANCH_REF_PREFIX + default_branch

                {
                  project_id: project.id,
                  default_branch: default_branch,
                  default_branch_head_sha: project.repository.commit(default_branch_ref)&.sha,
                  repository_storage: project.repository_storage
                }
              end

              namespace 'repository' do
                desc 'List repository branches' do
                  detail 'Returns a paginated list of repository branches with their commits'
                  tags 'orbit'
                  success code: 200, model: Entities::Branch, is_array: true
                  failure [{ code: 400, message: 'Bad request' }, { code: 404, message: 'Project not found' }]
                end
                params do
                  optional :sort, type: String, values: %w[name_asc updated_asc updated_desc],
                    desc: 'Return branches sorted by the given field'
                  optional :per_page, type: Integer, default: 20, except_values: [0],
                    desc: 'Number of branches per page'
                  optional :pagination, type: String, values: %w[keyset], default: 'keyset',
                    desc: 'Pagination method'
                  optional :page_token, type: String, limit: 1024,
                    desc: 'Record from which to continue keyset pagination'
                end
                route_setting :authorization, skip_granular_token_authorization: :orbit_internal_auth
                get '/branches', feature_category: :knowledge_graph, urgency: :low do
                  project = find_project_or_not_found!
                  normalize_repository_pagination!

                  if project.repository_exists?
                    branch_params = declared(params, include_missing: false, include_parent_namespaces: false)
                    branches_finder = ::Gitlab::Git::Finders::BranchesFinder.new(
                      project.repository.raw_repository,
                      branch_params,
                      include_commits: true
                    )
                    branches = Gitlab::Pagination::GitalyKeysetPager.new(self, project).paginate(branches_finder)
                  else
                    branches = []
                  end

                  present branches, with: Entities::Branch, project: project, only: %i[name commit]
                end

                desc 'List repository tree entries' do
                  detail 'Returns repository files and directories for the given ref and path'
                  tags 'orbit'
                  success code: 200, model: Entities::TreeObject, is_array: true
                  failure [{ code: 400, message: 'Bad request' }, { code: 404, message: 'Tree not found' }]
                end
                params do
                  optional :ref, type: String, limit: 1024,
                    desc: 'Branch, tag, or SHA. Defaults to the default branch.'
                  optional :path, type: String, limit: 1024, desc: 'Path of the tree'
                  optional :recursive, type: Boolean, default: false, desc: 'Return entries recursively'
                  optional :with_last_commit, type: Boolean, default: false,
                    desc: 'Include the last commit for each entry. Cannot be combined with recursive.'
                  use :pagination
                  optional :pagination, type: String, values: %w[legacy keyset none], default: 'keyset',
                    desc: 'Pagination method. None is only valid for recursive trees.'

                  given pagination: ->(value) { value == 'keyset' } do
                    optional :page_token, type: String, limit: 1024,
                      desc: 'Record from which to continue keyset pagination'
                  end

                  given pagination: ->(value) { value == 'none' } do
                    given recursive: ->(value) { value == false } do
                      validates([:pagination], except_values: {
                        value: 'none', message: 'cannot be "none" unless "recursive" is true'
                      })
                    end
                  end

                  given with_last_commit: ->(value) { value == true } do
                    validates([:recursive], except_values: {
                      value: [true], message: 'cannot be "true" when "with_last_commit" is "true"'
                    })
                  end
                end
                route_setting :authorization, skip_granular_token_authorization: :orbit_internal_auth
                get '/tree', feature_category: :knowledge_graph, urgency: :low do
                  project = find_project_or_not_found!
                  normalize_repository_pagination!
                  tree_params = declared(params, include_missing: false, include_parent_namespaces: false)
                  tree_finder = ::Repositories::TreeFinder.new(project, tree_params.merge(rescue_not_found: false))

                  not_found!('Tree') unless tree_finder.commit_exists?

                  tree = Gitlab::Pagination::GitalyKeysetPager.new(self, project).paginate(tree_finder)

                  present tree, with: Entities::TreeObject
                rescue Gitlab::Git::Index::IndexError => error
                  not_found!(error.message)
                end

                desc 'Download repository archive' do
                  detail 'Returns a tar.gz archive of the project repository at the given ref'
                  tags 'orbit'
                  success code: 200
                end
                params do
                  optional :ref, type: String,
                    desc: 'Git ref to archive (branch, tag, or SHA). Defaults to the default branch.'
                  optional :include_lfs_blobs, type: Boolean, default: true,
                    desc: 'Resolve Git LFS pointers to their object contents.'
                end
                route_setting :authorization, skip_granular_token_authorization: :orbit_internal_auth
                get '/archive', feature_category: :knowledge_graph, urgency: :low do
                  project = find_project_or_not_found!
                  ref = params[:ref] || project.default_branch_or_main

                  check_repository_archive_download!(project.repository)
                  audit_repository_archive_download(project.repository, client_name: ORBIT_CLIENT_NAME)

                  send_git_archive project.repository,
                    ref: ref,
                    format: 'tar.gz',
                    append_sha: false,
                    include_lfs_blobs: params[:include_lfs_blobs],
                    client_name: ORBIT_CLIENT_NAME
                rescue Gitlab::Workhorse::ArchiveNotFoundError, Gitlab::Git::Repository::NoRepository, RuntimeError => e
                  not_found!(e.message)
                end

                desc 'List repository commits' do
                  detail 'Returns a paginated list of commits for the given ref'
                  tags 'orbit'
                  success code: 200
                end
                params do
                  optional :ref, type: String, limit: 1024,
                    desc: 'Branch, tag, or SHA. Defaults to the default branch.'
                  optional :ref_name, type: String, limit: 1024,
                    desc: 'Branch, tag, or SHA. Defaults to the default branch.'
                  optional :since, type: DateTime, desc: 'Only commits after or on this date (ISO 8601)'
                  optional :until, type: DateTime, desc: 'Only commits before or on this date (ISO 8601)'
                  optional :path, type: String, limit: 1024, desc: 'File path to filter commits by'
                  optional :author, type: String, limit: 255, desc: 'Commit author to filter by'
                  optional :all, type: Boolean, desc: 'Return commits from all refs'
                  optional :first_parent, type: Boolean, desc: 'Only follow the first parent of merge commits'
                  optional :order, type: String, values: %w[default topo], default: 'default',
                    desc: 'Commit traversal order'
                  optional :per_page, type: Integer, desc: 'Number of commits per page',
                    default: 20, except_values: [0]
                  optional :page_token, type: String, limit: 1024,
                    desc: 'Record from which to continue keyset pagination'
                end
                route_setting :authorization, skip_granular_token_authorization: :orbit_internal_auth
                get '/commits', feature_category: :knowledge_graph, urgency: :low do
                  project = find_project_or_not_found!
                  normalize_repository_pagination!

                  if params[:ref].present? && params[:ref_name].present?
                    bad_request!('ref and ref_name cannot be used together')
                  end

                  commit_params = declared(params, include_missing: false, include_parent_namespaces: false)
                  commit_params[:ref_name] ||= commit_params.delete(:ref)
                  commits_finder = ::Repositories::CommitsFinder.new(project, commit_params)
                  commits = commits_finder.execute(gitaly_pagination: true)
                  if commits.size == params[:per_page] && commits_finder.next_cursor.present?
                    header 'X-Next-Page-Token', commits_finder.next_cursor
                  end

                  present commits, with: Entities::Commit
                rescue Gitlab::Git::CommandTimedOut
                  raise
                rescue ::Repositories::CommitsFinder::UnsupportedKeysetParamError,
                  Gitlab::Git::CommandError,
                  Gitlab::Git::Repository::CommitNotFound => error
                  bad_request!(error.message)
                end

                desc 'Stream changed file paths between two tree revisions' do
                  detail 'Returns changed paths as newline-delimited JSON via Workhorse. ' \
                    'Proxies to the Gitaly FindChangedPaths RPC. ' \
                    'Returns 400 if left_tree_revision is not an ancestor of right_tree_revision (force push).'
                  tags 'orbit'
                  success code: 200
                end
                params do
                  requires :left_tree_revision, type: String, desc: 'Base tree revision (commit SHA)'
                  requires :right_tree_revision, type: String, desc: 'Target tree revision (commit SHA)'
                end
                route_setting :authorization, skip_granular_token_authorization: :orbit_internal_auth
                get '/changed_paths', feature_category: :knowledge_graph, urgency: :low do
                  project = find_project_or_not_found!
                  repository = project.repository

                  validate_fast_forward!(repository, params[:left_tree_revision], params[:right_tree_revision])

                  requests = [
                    ::Gitaly::FindChangedPathsRequest::Request.new(
                      tree_request: ::Gitaly::FindChangedPathsRequest::Request::TreeRequest.new(
                        left_tree_revision: params[:left_tree_revision],
                        right_tree_revision: params[:right_tree_revision]
                      )
                    )
                  ]

                  header(*Gitlab::Workhorse.send_changed_paths(
                    repository,
                    requests,
                    client_name: ORBIT_CLIENT_NAME
                  ))
                  body ''
                rescue GRPC::NotFound
                  not_found!('Repository')
                end

                desc 'Stream changed file paths for a batch of commit comparisons' do
                  detail 'Compares each target commit against its explicit base, including divergent histories. ' \
                    'Returns newline-delimited JSON with the target commit ID for each changed path.'
                  tags 'orbit'
                  success code: 200
                end
                params do
                  requires :comparisons, type: Array, allow_blank: false, desc: 'Commit comparisons' do
                    requires :base_revision, type: String, allow_blank: false, regexp: Gitlab::Git::COMMIT_ID,
                      desc: 'Full SHA of the base commit'
                    requires :target_revision, type: String, allow_blank: false, regexp: Gitlab::Git::COMMIT_ID,
                      desc: 'Full SHA of the target commit'
                  end
                end
                route_setting :authorization, skip_granular_token_authorization: :orbit_internal_auth
                post '/changed_paths', feature_category: :knowledge_graph, urgency: :low do
                  comparisons = params[:comparisons]
                  if comparisons.size > MAX_CHANGED_PATHS_COMPARISONS
                    bad_request!("comparisons is limited to #{MAX_CHANGED_PATHS_COMPARISONS} entries")
                  end

                  targets = comparisons.map { |comparison| comparison[:target_revision].downcase }
                  bad_request!('target_revision must be unique within comparisons') if targets.uniq.size != targets.size

                  project = find_project_or_not_found!
                  requests = comparisons.map do |comparison|
                    ::Gitaly::FindChangedPathsRequest::Request.new(
                      commit_request: ::Gitaly::FindChangedPathsRequest::Request::CommitRequest.new(
                        commit_revision: comparison[:target_revision].downcase,
                        parent_commit_revisions: [comparison[:base_revision].downcase]
                      )
                    )
                  end

                  status 200
                  header(*Gitlab::Workhorse.send_changed_paths(
                    project.repository,
                    requests,
                    client_name: ORBIT_CLIENT_NAME
                  ))
                  body ''
                end

                desc 'Stream blob contents for given revisions' do
                  detail 'Returns blobs as length-prefixed protobuf frames via Workhorse. ' \
                    'Proxies to the Gitaly ListBlobs RPC. ' \
                    'Blobs larger than bytes_limit are truncated.'
                  tags 'orbit'
                  success code: 200
                end
                params do
                  requires :revisions, type: Array[String], allow_blank: false,
                    desc: 'Git revisions to list blobs for'
                  optional :bytes_limit, type: Integer, default: BLOB_BYTES_LIMIT,
                    values: 1..BLOB_BYTES_LIMIT,
                    desc: "Maximum blob size in bytes (1 to #{BLOB_BYTES_LIMIT})"
                end
                route_setting :authorization, skip_granular_token_authorization: :orbit_internal_auth
                post '/list_blobs', feature_category: :knowledge_graph, urgency: :low do
                  if params[:revisions].size > MAX_LIST_BLOBS_REVISIONS
                    bad_request!("revisions is limited to #{MAX_LIST_BLOBS_REVISIONS} entries")
                  end

                  project = find_project_or_not_found!
                  status 200

                  header(*Gitlab::Workhorse.send_list_blobs(
                    project.repository,
                    params[:revisions],
                    client_name: ORBIT_CLIENT_NAME,
                    bytes_limit: params[:bytes_limit]
                  ))
                  body ''
                end
              end

              namespace 'merge_requests' do
                route_param :merge_request_iid, type: Integer, desc: 'MR IID (project-scoped)' do
                  desc 'Return the raw diff of the latest version of a merge request' do
                    detail 'Returns the unified patch for the most recent MergeRequestDiff, ' \
                      'streamed as text/plain via Workhorse.'
                    tags 'orbit'
                    success code: 200
                  end
                  route_setting :authorization, skip_granular_token_authorization: :orbit_internal_auth
                  get '/raw_diffs', feature_category: :knowledge_graph, urgency: :low do
                    project = find_project_or_not_found!
                    merge_request = project.merge_requests.find_by_iid!(params[:merge_request_iid])

                    diff_refs = merge_request.diff_refs
                    not_found!('merge_request has no diff refs') unless diff_refs

                    send_git_diff(project.repository, diff_refs, client_name: ORBIT_CLIENT_NAME)
                  end
                end
              end

              namespace 'merge_request_diffs' do
                route_param :diff_id, type: Integer, desc: 'MergeRequestDiff.id' do
                  desc 'Return per-file diffs for a MergeRequestDiff' do
                    detail 'Reads persisted MergeRequestDiffFile diffs which covers in-PG, ' \
                      'external object storage, and live Gitaly recompute.'
                    tags 'orbit'
                    success code: 200
                  end
                  params do
                    optional :paths, type: Array[String],
                      desc: 'Filter to these (new_path or old_path) entries, max 100.'
                  end
                  route_setting :authorization, skip_granular_token_authorization: :orbit_internal_auth
                  get '/', feature_category: :knowledge_graph, urgency: :low do
                    project = find_project_or_not_found!
                    diff_record = find_merge_request_diff_or_not_found!(project)

                    paths = params[:paths]
                    bad_request!('paths limited to 100 entries') if paths.present? && paths.size > 100

                    diffs = diff_record.raw_diffs(paths: paths.presence).first(100)

                    status 200
                    {
                      id: diff_record.id,
                      head_commit_sha: diff_record.head_commit_sha,
                      base_commit_sha: diff_record.base_commit_sha,
                      start_commit_sha: diff_record.start_commit_sha,
                      diffs: Entities::Diff.represent(diffs, enable_unidiff: true)
                    }
                  end

                  desc 'Return the full unified patch for a MergeRequestDiff' do
                    detail 'Returns all persisted file diffs concatenated as a single text/plain unified patch.'
                    tags 'orbit'
                    success code: 200
                  end
                  route_setting :authorization, skip_granular_token_authorization: :orbit_internal_auth
                  get '/raw_diffs', feature_category: :knowledge_graph, urgency: :low do
                    project = find_project_or_not_found!
                    diff_record = find_merge_request_diff_or_not_found!(project)

                    diff_refs = diff_record.diff_refs
                    not_found!('merge_request_diff has no diff refs') unless diff_refs

                    send_git_diff(project.repository, diff_refs, client_name: ORBIT_CLIENT_NAME)
                  end
                end
              end
            end
          end
        end
      end
    end
  end
end
