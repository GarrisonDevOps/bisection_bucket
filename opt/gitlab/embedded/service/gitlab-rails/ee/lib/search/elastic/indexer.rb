# frozen_string_literal: true

# Create a separate process, which does not load the Rails environment, to index
# each repository. This prevents memory leaks in the indexer from affecting the
# rest of the application.
module Search
  module Elastic
    class Indexer
      include Gitlab::Utils::StrongMemoize
      include Gitlab::Loggable

      TIMEOUT_MINUTES = 30 # Default timeout, overridden by application setting
      Error = Class.new(StandardError)
      BLOB_SCHEMA_VERSION = 23_08
      COMMIT_SCHEMA_VERSION = 23_06
      WIKI_SCHEMA_VERSION = 25_06

      ORGANIZATION_FIELDS_MIGRATIONS = {
        blob: :add_organization_fields_to_main_index,
        commit: :add_organization_fields_to_commits,
        wiki: :add_organization_fields_to_wikis
      }.freeze

      class << self
        def indexer_version
          Rails.root.join('GITLAB_ELASTICSEARCH_INDEXER_VERSION').read.chomp
        end

        def timeout
          Gitlab::CurrentSettings.elasticsearch_indexing_timeout_minutes.minutes
        end
      end

      attr_reader :container, :project, :group, :index_status, :wiki, :force
      alias_method :index_wiki?, :wiki
      alias_method :force_reindexing?, :force

      def initialize(container, wiki: false, force: false)
        case container
        when Project
          @project = container
          @group = container.group
        when Group
          @group = container
        end

        @container = container
        @wiki = wiki
        @force = force

        # Use the eager-loaded association if available.
        @index_status = container.index_status
      end

      # Runs the indexation process, which is the following:
      # - Purge the index for any unreachable commits;
      # - Run the `gitlab-elasticsearch-indexer`;
      # - Update the `index_status` for the associated project;
      #
      # ref - Git ref up to which the indexation will run (default: nil)
      # Default uses root_ref to avoid when HEAD points to non-existent branch
      # https://gitlab.com/gitlab-org/gitaly/-/issues/1446
      def run(ref = nil)
        commit = find_indexable_commit(ref)
        commit_sha = commit&.sha

        repository.__elasticsearch__.elastic_writing_targets.each do |target|
          logger.debug(
            build_structured_payload(
              message: 'indexing_commit_range',
              group_id: group&.id,
              project_id: project&.id,
              from_sha: from_sha,
              to_sha: commit_sha,
              index_wiki: index_wiki?
            )
          )

          # This might happen when default branch has been reset or rebased.
          base_sha = if purge_unreachable_commits_from_index?(commit_sha)
                       purge_unreachable_commits_from_index!(target)

                       repository.empty_tree_id
                     else
                       from_sha
                     end

          run_indexer!(base_sha, commit_sha, target) if commit_sha
        end

        # update the index status only if all writes were successful
        update_index_status(commit_sha || Gitlab::Git::SHA1_BLANK_SHA)

        true
      end

      private

      def find_indexable_commit(ref)
        return if repository.empty?

        repository.commit(ref)
      end

      def purge_unreachable_commits_from_index?(to_sha)
        to_sha.blank? || force_reindexing? || !last_commit_ancestor_of?(to_sha)
      end

      def repository
        index_wiki? ? container.wiki.repository : container.repository
      end

      def run_indexer!(base_sha, to_sha, target)
        vars = build_envvars(target)
        command = build_command(base_sha, to_sha)

        output, status = Gitlab::Popen.popen(command, nil, vars)

        return if status.blank?

        payload = build_structured_payload(
          message: output,
          status: status,
          group_id: group&.id,
          project_id: project&.id,
          from_sha: base_sha,
          to_sha: to_sha,
          index_wiki: index_wiki?
        )

        if status == 0
          logger.info(payload)
        else
          logger.error(payload)
          raise Error, output
        end
      end

      # Remove all indexed data for commits and blobs for a project.
      #
      # @return: whether the index has been purged
      def purge_unreachable_commits_from_index!(target)
        target.delete_index_for_commits_and_blobs(is_wiki: index_wiki?)
      rescue ::Elasticsearch::Transport::Transport::Errors::BadRequest => e
        Gitlab::ErrorTracking.track_exception(e, group_id: group&.id, project_id: project&.id)
      end

      def build_envvars(target)
        # We accept any form of settings, including string and array
        # This is why JSON is needed
        vars = {
          'RAILS_ENV' => Rails.env,
          'ELASTIC_CONNECTION_INFO' => elasticsearch_config(target),
          'GITALY_CONNECTION_INFO' => gitaly_config,
          'CORRELATION_ID' => Labkit::Correlation::CorrelationId.current_id,
          'SSL_CERT_FILE' => Gitlab::X509::Certificate.default_cert_file,
          'SSL_CERT_DIR' => Gitlab::X509::Certificate.default_cert_dir
        }

        # Set AWS environment variables for IAM role authentication if present
        vars = build_aws_credentials_env(vars) if Gitlab::CurrentSettings.elasticsearch_config[:aws]

        # Users can override default SSL certificate path via SSL_CERT_FILE SSL_CERT_DIR
        vars.merge(ENV.slice('SSL_CERT_FILE', 'SSL_CERT_DIR'))
      end

      def build_command(base_sha, to_sha)
        path_to_indexer = Gitlab.config.elasticsearch.indexer_path
        timeout_argument = "--timeout=#{self.class.timeout.to_i}s"
        visibility_level_argument = "--visibility-level=#{container.visibility_level}"

        command = [path_to_indexer, timeout_argument, visibility_level_argument]

        command << "--group-id=#{group.id}" if group
        command << "--project-id=#{project.id}" if project
        command << "--from-sha=#{base_sha}"
        command << "--to-sha=#{to_sha}"
        command << "--full-path=#{container.full_path}"

        command += if index_wiki?
                     build_wiki_specific_flags
                   else
                     build_blob_specific_flags
                   end

        command << "--traversal-ids=#{traversal_ids}"
        command << "--organization-id=#{container.organization_id}"
        command << "--organization-traversal-ids=#{organization_traversal_ids}"

        command << repository_path
      end

      # `container` is a Project or a Group, and the constructor sets `project` only for
      # the former, so this covers both without a third, unreachable branch.
      def traversal_ids
        project ? project.namespace_ancestry : group.elastic_namespace_ancestry
      end

      # `<organization_id>/<traversal_ids>`, for example `24/9970-123-456-`. Mirrors
      # `--traversal-ids` exactly so a prefix query behaves the same on both. Namespace ids
      # are only unique within an organization, so a prefix query over traversal_ids alone
      # can match a namespace that belongs to a different one.
      def organization_traversal_ids
        return if container.organization_id.blank? || traversal_ids.blank?

        "#{container.organization_id}/#{traversal_ids}"
      end

      # Blobs, commits and wiki blobs live in three different indices, each with its own
      # mapping migration. The indexer only writes the organization fields onto a document
      # type once we tell it that type's mapping is ready.
      def organization_fields_enabled?(document_type)
        ::Elastic::DataMigrationService.migration_has_finished?(
          ORGANIZATION_FIELDS_MIGRATIONS.fetch(document_type)
        )
      end

      def build_wiki_specific_flags
        %W[--blob-type=wiki_blob --skip-commits --wiki-access-level=#{container.wiki_access_level}].tap do |c|
          c << "--archived=#{project.self_or_ancestors_archived?}" if project
          c << "--schema-version-wiki=#{WIKI_SCHEMA_VERSION}"
          c << "--organization-fields-enabled-wiki=#{organization_fields_enabled?(:wiki)}"
        end
      end

      def build_blob_specific_flags
        %W[--repository-access-level=#{container.repository_access_level}].tap do |c|
          c << "--hashed-root-namespace-id=#{project.namespace.hashed_root_namespace_id}"
          c << "--schema-version-blob=#{BLOB_SCHEMA_VERSION}"
          c << "--schema-version-commit=#{COMMIT_SCHEMA_VERSION}"
          c << "--archived=#{project.self_or_ancestors_archived?}"
          c << '--skip-blobs' unless Gitlab::CurrentSettings.elasticsearch_code_scope
          c << '--commit-traversal-ids-enabled=true'
          c << "--organization-fields-enabled-blob=#{organization_fields_enabled?(:blob)}"
          c << "--organization-fields-enabled-commit=#{organization_fields_enabled?(:commit)}"
        end
      end

      def build_aws_credentials_env(vars)
        # AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN need to be set as
        # environment variable in case of using IAM role based authentication in AWS
        # The credentials are buffered to prevent from hitting rate limit. They will be
        # refreshed when expired
        # Static credentials will be used if it is set
        elastic_config = Gitlab::CurrentSettings.elasticsearch_config
        credentials = ::Search::Elastic::Client.resolve_aws_credentials(elastic_config)&.credentials

        return vars unless credentials&.set?

        vars.merge(
          'AWS_ACCESS_KEY_ID' => credentials.access_key_id,
          'AWS_SECRET_ACCESS_KEY' => credentials.secret_access_key,
          'AWS_SESSION_TOKEN' => credentials.session_token
        )
      end

      def last_commit
        index_wiki? ? index_status&.last_wiki_commit : index_status&.last_commit
      end

      def from_sha
        repository_contains_last_indexed_commit? ? last_commit : repository.empty_tree_id
      end
      strong_memoize_attr :from_sha

      def repository_contains_last_indexed_commit?
        last_commit.present? && repository.commit(last_commit).present?
      end
      strong_memoize_attr :repository_contains_last_indexed_commit?

      def last_commit_ancestor_of?(to_sha)
        return true if Gitlab::Git.blank_ref?(from_sha)
        return false unless repository_contains_last_indexed_commit?

        # we always treat the empty tree id as an ancestor to make sure
        # we don't try to purge an empty index
        from_sha == repository.empty_tree_id || repository.ancestor?(from_sha, to_sha)
      end

      def repository_path
        "#{repository.disk_path}.git"
      end

      def elasticsearch_config(target)
        config = Gitlab::CurrentSettings.elasticsearch_config.merge(
          index_name: target.index_name,
          index_name_commits: ::Elastic::Latest::CommitConfig.index_name,
          index_name_wikis: ::Elastic::Latest::WikiConfig.index_name
        )

        # We need to pass a percent encoded URL string instead of a hash
        # to the go indexer because it passes authentication credentials
        # embedded in the url.
        #
        # https://gitlab.com/gitlab-org/gitlab-elasticsearch-indexer/-/blob/v5.13.3/internal/mode/advanced/elastic/elastic.go#L25
        config[:url] = config[:url].map { |u| ::Search::Elastic::Helper.url_string(u) }
        config.to_json
      end

      def gitaly_config
        {
          storage: container.repository_storage,
          limit_file_size: Gitlab::CurrentSettings.elasticsearch_indexed_file_size_limit_kb.kilobytes
        }.merge(Gitlab::GitalyClient.connection_data(container.repository_storage)).to_json
      end

      def update_index_status(to_sha)
        unless container.class.name.constantize.id_in(container.id).exists?
          logger.debug(build_structured_payload(
            message: "Index status not updated. The #{container.class.name.downcase} does not exist.",
            group_id: group&.id,
            project_id: project&.id,
            index_wiki: index_wiki?
          ))
          return false
        end

        raise "Invalid sha #{to_sha}" unless to_sha.present?

        # An index_status should always be created,
        # even if the repository is empty, so we know it's been looked at.
        case container
        when Project
          @index_status ||= IndexStatus.safe_find_or_create_by!(project_id: project.id)
        when Group
          @index_status ||= ::Elastic::GroupIndexStatus.safe_find_or_create_by!(namespace_id: group.id)
        end

        attributes = if index_wiki?
                       { last_wiki_commit: to_sha, wiki_indexed_at: Time.zone.now }
                     else
                       { last_commit: to_sha, indexed_at: Time.zone.now }
                     end

        @index_status.update!(attributes)

        container.reload_index_status
      rescue ActiveRecord::InvalidForeignKey
        logger.debug(
          build_structured_payload(message: "Index status not created, #{container.class.name.downcase} not found",
            group_id: group&.id, project_id: project&.id)
        )
      end

      def logger
        @logger ||= ::Gitlab::Elasticsearch::Logger.build
      end
    end
  end
end
