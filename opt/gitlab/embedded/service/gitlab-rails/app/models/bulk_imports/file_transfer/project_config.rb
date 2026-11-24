# frozen_string_literal: true

module BulkImports
  module FileTransfer
    class ProjectConfig < BaseConfig
      SKIPPED_RELATIONS = %w[
        group_members
      ].freeze

      # Direct transfer fetches snippet repositories over git, so only offline exports need the bundles
      DIRECT_TRANSFER_SKIPPED_RELATIONS = %w[project_members snippet_repositories].freeze

      LFS_OBJECTS_RELATION = 'lfs_objects'
      REPOSITORY_BUNDLE_RELATION = 'repository'
      DESIGN_BUNDLE_RELATION = 'design'
      COMMIT_NOTES_RELATION = 'commit_notes'
      SNIPPET_REPOSITORIES_RELATION = 'snippet_repositories'

      def import_export_yaml
        ::Gitlab::ImportExport.config_file
      end

      def skipped_relations
        return SKIPPED_RELATIONS if offline?

        SKIPPED_RELATIONS + DIRECT_TRANSFER_SKIPPED_RELATIONS
      end

      def file_relations
        [
          UPLOADS_RELATION,
          LFS_OBJECTS_RELATION,
          REPOSITORY_BUNDLE_RELATION,
          DESIGN_BUNDLE_RELATION,
          SNIPPET_REPOSITORIES_RELATION
        ]
      end

      def export_service_for(relation)
        return ::Import::BulkImports::CommitNotesExportService if commit_notes_export_via_git?(relation)

        super
      end

      def batchable_relation?(relation)
        return true if commit_notes_export_via_git?(relation)
        # Project has a snippet_repositories association, but the bundles are exported as one archive
        return false if relation == SNIPPET_REPOSITORIES_RELATION

        super
      end

      def commit_notes_export_via_git?(relation)
        relation == COMMIT_NOTES_RELATION
      end
    end
  end
end
