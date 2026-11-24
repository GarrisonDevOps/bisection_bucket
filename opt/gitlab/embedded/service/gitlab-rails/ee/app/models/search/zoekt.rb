# frozen_string_literal: true

module Search
  module Zoekt
    MissingFeatureError = Class.new(StandardError)

    EXPIRED_SUBSCRIPTION_GRACE_PERIOD = 30.days
    MAX_INDICES_PER_REPLICA = 10

    class << self
      include Gitlab::Utils::StrongMemoize

      def search?(container)
        return false unless search_enabled?
        return Node.for_search.searchable.exists? if container.nil?

        root_namespace_id = fetch_root_namespace_id(container)
        return false unless root_namespace_id
        return Replica.search_enabled?(root_namespace_id) if search_with_replica?(container, root_namespace_id)

        Index.for_root_namespace_id_with_search_enabled(root_namespace_id).ready.exists?
      end

      def index?(container)
        return false unless licensed_and_indexing_enabled?

        root_namespace_id = fetch_root_namespace_id(container)
        return false unless root_namespace_id

        Index.for_root_namespace_id(root_namespace_id).exists?
      end

      def licensed_and_indexing_enabled?
        ::License.feature_available?(:zoekt_code_search) && ::Gitlab::CurrentSettings.zoekt_indexing_enabled?
      end

      def search_enabled?
        return false unless ::License.feature_available?(:zoekt_code_search)
        return false unless ::Gitlab::CurrentSettings.zoekt_search_enabled?

        true
      end

      def feature_available?(feature_name, user = nil, project_id: nil, group_id: nil)
        feature_class = "Search::Zoekt::Features::#{feature_name.to_s.camelize}".safe_constantize
        raise MissingFeatureError, "Zoekt feature '#{feature_name}' does not exist" if feature_class.nil?

        feature_class.available?(user, project_id: project_id, group_id: group_id)
      end

      def index_async(project_id)
        return false unless licensed_and_indexing_enabled?

        IndexingTaskWorker.perform_async(project_id, 'index_repo')
      end

      def bulk_index_async(project_ids, task_type: 'index_repo')
        return false unless licensed_and_indexing_enabled?

        project_ids.each_slice(IndexingTaskBatchWorker::BATCH_SIZE) do |batch|
          tasks = batch.map { |pid| [pid, task_type, {}] }
          IndexingTaskBatchWorker.perform_async(tasks)
        end
        project_ids.size
      end

      def index_in(delay, project_id)
        return false unless licensed_and_indexing_enabled?

        IndexingTaskWorker.perform_async(project_id, 'index_repo', { delay: delay })
      end

      def delete_async(project_id, root_namespace_id:, node_id: nil)
        return false unless licensed_and_indexing_enabled?

        Router.fetch_nodes_for_indexing(project_id, root_namespace_id: root_namespace_id,
          node_ids: [node_id]).map do |node|
          options = { root_namespace_id: root_namespace_id, node_id: node.id }
          IndexingTaskWorker.perform_async(project_id, 'delete_repo', options)
        end
      end

      # @param project [Project, nil]
      # @return [Object] the block's return value
      def with_project_context(project, &block)
        # ApplicationContext reads the root namespace ID and plan only from a loaded namespace.
        project&.namespace

        ::Gitlab::ApplicationContext.with_context(project: project, organization: project&.organization, &block)
      end

      def bin_path
        Gitlab.config.zoekt.bin_path
      end

      def missing_repo?(project)
        !project.repo_exists? || project.empty_repo?
      end

      private

      def fetch_root_namespace_id(container)
        case container
        in Project | Namespace
          container.root_ancestor.id
        in Integer => root_namespace_id
          root_namespace_id
        else
          raise ArgumentError, "#{container.class} class is not supported"
        end
      end

      def search_with_replica?(container, _root_namespace_id)
        !container.is_a?(Project)
      end
    end
  end
end
