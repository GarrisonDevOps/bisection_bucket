# frozen_string_literal: true

module Ai
  module DapFactory
    class ConfigurationFile
      include ::Gitlab::Utils::StrongMemoize

      attr_reader :project

      def initialize(project)
        @project = project
      end

      def path
        ::Gitlab::Ai::DapFactory::Configuration::PATH
      end

      def default_branch
        project.default_branch
      end

      # The last commit that touched the file, as the Files API reports it, so a stale save fails.
      def last_commit_id
        return unless exists?

        project.repository.last_commit_id_for_path(commit.id, path, literal_pathspec: true)
      end
      strong_memoize_attr :last_commit_id

      def exists?
        !blob_data.nil?
      end

      # Oversized content is withheld rather than truncated, so the editor cannot open a cut-off file
      # and save it back over the tail. The :too_large validation error explains the blank.
      def content
        return if too_large?

        blob_data
      end

      def validation
        return unless exists?

        ::Gitlab::Ai::DapFactory::Validator.new(content: blob_data, project: project).execute
      end
      strong_memoize_attr :validation

      def errors
        validation&.errors || []
      end

      def warnings
        validation&.warnings || []
      end

      def last_sync
        SyncResult.for(project)
      end

      private

      def blob_data
        return unless commit

        project.repository.blob_at(commit.id, path, limit: ::Gitlab::Ai::DapFactory::Validator::READ_LIMIT)&.data
      end
      strong_memoize_attr :blob_data

      def too_large?
        !blob_data.nil? && blob_data.bytesize > ::Gitlab::Ai::DapFactory::Validator::MAX_BYTES
      end

      def commit
        return if default_branch.blank?

        project.repository.commit(default_branch)
      end
      strong_memoize_attr :commit
    end
  end
end
