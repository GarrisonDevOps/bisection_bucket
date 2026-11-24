# frozen_string_literal: true

module Gitlab
  module BackgroundMigration
    class MarkDuplicateDefaultTrackedContextsAsNonDefault < BatchedMigrationJob
      cursor :id

      operation_name :mark_duplicate_default_tracked_contexts_as_non_default
      feature_category :vulnerability_management

      BRANCH_CONTEXT_TYPE = 1
      TRANSIENT_GITALY_ERRORS = [::Gitlab::Git::CommandTimedOut, ::Gitlab::Git::ResourceExhaustedError].freeze
      # Code bugs re-raise too, so they fail the batch instead of showing up as skipped projects.
      CODE_ERRORS = [::NameError, ::TypeError].freeze
      # Building the project path can query the main database when the route row is missing.
      TRANSIENT_DATABASE_ERRORS = [::ActiveRecord::QueryAborted, ::ActiveRecord::ConnectionNotEstablished].freeze

      def perform
        each_sub_batch do |sub_batch|
          project_ids = duplicate_project_ids(sub_batch)
          next if project_ids.empty?

          contexts_by_project = default_contexts_by_project(project_ids)
          next if contexts_by_project.empty?

          projects_by_id = Project.where(id: contexts_by_project.keys).preload(:route).index_by(&:id)

          contexts_by_project.each do |project_id, contexts|
            default_branch = default_branch_for(projects_by_id[project_id])
          rescue StandardError => e # rubocop:disable BackgroundMigration/AvoidSilentRescueExceptions -- skip and log so one broken repository can't fail the migration
            raise if transient_error?(e) || CODE_ERRORS.any? { |klass| e.is_a?(klass) }

            log_skip(
              'after an error reading the default branch', project_id, contexts,
              Labkit::Fields::ERROR_TYPE => e.class.name, Labkit::Fields::ERROR_MESSAGE => e.message
            )
          else
            keep = matching_context(contexts, default_branch)

            if keep
              mark_non_default(project_id, contexts, keep)
            else
              log_skip('with no default branch match', project_id, contexts, default_branch: default_branch)
            end
          end
        end
      end

      private

      def duplicate_project_ids(sub_batch)
        sub_batch_project_ids = SecurityProjectTrackedContext
          .where(id: sub_batch.select(:id), is_default: true)
          .distinct
          .select(:project_id)

        SecurityProjectTrackedContext
          .where(project_id: sub_batch_project_ids, is_default: true)
          .group(:project_id)
          .having('COUNT(*) > 1')
          .pluck(:project_id)
      end

      def default_contexts_by_project(project_ids)
        SecurityProjectTrackedContext
          .where(project_id: project_ids, is_default: true)
          .select(:id, :project_id, :context_name, :context_type)
          .group_by(&:project_id)
          .select { |_project_id, contexts| contexts.size > 1 }
      end

      def default_branch_for(project)
        ::Gitlab::GitalyClient.allow_n_plus_1_calls { project&.default_branch.presence }
      end

      def matching_context(contexts, default_branch)
        return unless default_branch

        contexts.find do |context|
          context.context_type == BRANCH_CONTEXT_TYPE && context.context_name == default_branch
        end
      end

      def mark_non_default(project_id, contexts, keep)
        flipped_ids = contexts.map(&:id) - [keep.id]

        updated_count = SecurityProjectTrackedContext
          .where(id: flipped_ids, is_default: true)
          .update_all(is_default: false, updated_at: Time.current)

        log_args = { message: 'Marked duplicate default tracked contexts as non-default', migration: self.class.name,
                     Labkit::Fields::GL_PROJECT_ID => project_id, kept_id: keep.id, flipped_ids: flipped_ids,
                     updated_count: updated_count }

        # Fewer updated rows than flipped_ids means another process changed them first.
        if updated_count < flipped_ids.size
          ::Gitlab::BackgroundMigration::Logger.warn(**log_args)
        else
          ::Gitlab::BackgroundMigration::Logger.info(**log_args)
        end
      end

      def log_skip(reason, project_id, contexts, **details)
        ::Gitlab::BackgroundMigration::Logger.warn(
          message: "Skipped duplicate default tracked contexts #{reason}",
          migration: self.class.name,
          Labkit::Fields::GL_PROJECT_ID => project_id,
          tracked_context_ids: contexts.map(&:id),
          **details
        )
      end

      def transient_error?(error)
        case error
        when *TRANSIENT_GITALY_ERRORS, *TRANSIENT_DATABASE_ERRORS
          true
        when ::Gitlab::Git::CommandError
          # Gitaly maps DEADLINE_EXCEEDED to CommandTimedOut, so only UNAVAILABLE is left here.
          error.status == GRPC::Core::StatusCodes::UNAVAILABLE
        else
          false
        end
      end

      class SecurityProjectTrackedContext < ::SecApplicationRecord
        self.table_name = 'security_project_tracked_contexts'
      end

      module Routable
        extend ActiveSupport::Concern

        included do
          self.store_full_class_name = false

          has_one :route, as: :source
        end

        def full_path
          route&.path || build_full_path
        end

        def build_full_path
          if parent && path
            "#{parent.full_path}/#{path}"
          else
            path
          end
        end
      end

      class Route < ::ApplicationRecord
        self.table_name = 'routes'
      end

      class Namespace < ::ApplicationRecord
        include Routable

        self.table_name = 'namespaces'
        self.inheritance_column = :_type_disabled

        belongs_to :parent,
          class_name: '::Gitlab::BackgroundMigration::MarkDuplicateDefaultTrackedContextsAsNonDefault::Namespace'
      end

      class Repository
        def initialize(full_path, container, shard:, disk_path:)
          @full_path = full_path
          @shard = shard
          @disk_path = disk_path || full_path
          @container = container
        end

        def root_ref
          raw_repository&.root_ref
        rescue ::Gitlab::Git::Repository::NoRepository
          nil
        end

        private

        attr_reader :full_path, :shard, :disk_path, :container

        def raw_repository
          return unless full_path

          @raw_repository ||= ::Gitlab::Git::Repository.new(
            shard,
            "#{disk_path}.git",
            ::Gitlab::GlRepository::PROJECT.identifier_for_container(container),
            container.full_path,
            container: container
          )
        end
      end

      module Storage
        class Hashed
          REPOSITORY_PATH_PREFIX = '@hashed'

          attr_accessor :container

          def initialize(container)
            @container = container
          end

          def disk_path
            "#{base_dir}/#{disk_hash}" if disk_hash
          end

          private

          def base_dir
            "#{REPOSITORY_PATH_PREFIX}/#{disk_hash[0..1]}/#{disk_hash[2..3]}" if disk_hash
          end

          def disk_hash
            @disk_hash ||= Digest::SHA2.hexdigest(container.id.to_s) if container.id
          end
        end

        class LegacyProject
          attr_accessor :project

          def initialize(project)
            @project = project
          end

          def disk_path
            project.full_path
          end
        end
      end

      class Project < ::ApplicationRecord
        include Routable

        self.table_name = 'projects'

        belongs_to :namespace,
          class_name: '::Gitlab::BackgroundMigration::MarkDuplicateDefaultTrackedContextsAsNonDefault::Namespace'
        alias_method :parent, :namespace

        has_one :route,
          as: :source,
          class_name: '::Gitlab::BackgroundMigration::MarkDuplicateDefaultTrackedContextsAsNonDefault::Route'

        def default_branch
          repository.root_ref
        end

        def repository
          @repository ||= Repository.new(
            full_path, self, shard: repository_storage, disk_path: storage.disk_path
          )
        end

        private

        def storage
          @storage ||=
            if storage_version.to_i >= 1
              Storage::Hashed.new(self)
            else
              Storage::LegacyProject.new(self)
            end
        end
      end
    end
  end
end
