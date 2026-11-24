# frozen_string_literal: true

module Search
  module Zoekt
    class TaskSerializerService
      KNOWLEDGE_GRAPH_INDEXING_TIMEOUT_S = 1.5.hours.to_i
      attr_reader :task, :node

      def self.execute(...)
        new(...).execute
      end

      def initialize(task, node)
        @task = task
        @node = node
      end

      def execute
        case task.task_type.to_sym
        when :index_repo
          {
            name: :index,
            payload: index_repo_payload
          }
        when :force_index_repo
          {
            name: :index,
            payload: force_index_repo_payload
          }
        when :delete_repo
          {
            name: :delete,
            payload: delete_repo_payload
          }
        else
          raise ArgumentError, "Unknown task_type: #{task.task_type.inspect}"
        end
      end

      private

      def index_repo_payload
        project = task.zoekt_repository.project

        gitaly_payload(project).merge(
          Callback: { name: 'index', payload: { task_id: task.id, schema_version: node.schema_version } },
          RepoID: project.id,
          ProjectFullPath: project.path_with_namespace,
          FileSizeLimit: ::Search::Zoekt::Settings.file_size_limit,
          Parallelism: ::Gitlab::CurrentSettings.zoekt_indexing_parallelism,
          Timeout: "#{::Search::Zoekt::Settings.indexing_timeout.to_i}s",
          FileCountLimit: ::Gitlab::CurrentSettings.zoekt_maximum_files,
          TrigramMax: ::Gitlab::CurrentSettings.zoekt_trigram_max,
          MissingRepo: ::Search::Zoekt.missing_repo?(project),
          Metadata: {
            project_id: project.id,
            traversal_ids: project.namespace_ancestry,
            organization_traversal_ids: project.namespace.organization_namespace_ancestry,
            visibility_level: project.visibility_level,
            repository_access_level: project.repository_access_level,
            forked: project.forked? ? "t" : "f",
            archived: project.self_or_ancestors_archived? ? "t" : "f"
          }.transform_values(&:to_s)
        )
      end

      def force_index_repo_payload
        index_repo_payload.merge(Force: true)
      end

      def delete_repo_payload
        {
          RepoID: task.project_identifier,
          Callback: { name: 'delete', payload: { task_id: task.id, service_type: :zoekt } }
        }
      end

      def gitaly_payload(project)
        return {} if ::Search::Zoekt.missing_repo?(project)

        repository_storage = project.repository_storage
        connection_info = Gitlab::GitalyClient.connection_data(repository_storage)
        repository_path = "#{project.repository.disk_path}.git"
        address = connection_info['address']

        # This code is needed to support relative unix: connection strings. For example, specs
        if address.match?(%r{\Aunix:[^/.]})
          path = address.split('unix:').last
          address = "unix:#{Rails.root.join(path)}"
        end

        {
          GitalyConnectionInfo: {
            Address: address,
            Token: connection_info['token'],
            Storage: repository_storage,
            Path: repository_path
          }
        }
      end
    end
  end
end
