# frozen_string_literal: true

module Import
  module Offline
    module Exports
      class SnippetRepositoriesExportService
        def initialize(portable, export_path)
          @portable = portable
          @export_path = export_path
          @exported_objects_count = 0
        end

        def execute(_options = {})
          ambiguous_bundle_filenames = ::Import::Offline::SnippetRepositoryBundle.ambiguous_filenames(portable)

          # Counts skipped snippets too, so the importer's source count matches its fetched count
          portable.snippets.preload_repository_shard.find_each do |snippet|
            @exported_objects_count += 1
            bundle_filename = ::Import::Offline::SnippetRepositoryBundle.filename_for(snippet)

            if ambiguous_bundle_filenames.include?(bundle_filename)
              log_ambiguous_snippet(snippet)
              next
            end

            export_bundle(snippet, bundle_filename)
          end
        end

        attr_reader :exported_objects_count

        private

        attr_reader :portable, :export_path

        # Skips the snippet rather than failing the relation, which would drop every snippet's repository
        def export_bundle(snippet, bundle_filename)
          bundle_path = File.join(export_path, bundle_filename)

          ::BulkImports::RepositoryBundleExportService.new(
            snippet.repository, export_path, File.basename(bundle_filename, '.bundle')
          ).execute
        rescue StandardError => e
          FileUtils.rm_f(bundle_path)

          Gitlab::ErrorTracking.log_exception(
            e,
            Labkit::Fields::GL_PROJECT_ID => portable.id,
            snippet_id: snippet.id,
            importer: ::Import::SOURCE_OFFLINE_TRANSFER
          )
        end

        def log_ambiguous_snippet(snippet)
          Gitlab::Export::Logger.warn(
            Labkit::Fields::GL_PROJECT_ID => portable.id,
            message: 'Skipping snippet repository export: ' \
              'another snippet in the project has the same title and creation time',
            snippet_id: snippet.id
          )
        end
      end
    end
  end
end
