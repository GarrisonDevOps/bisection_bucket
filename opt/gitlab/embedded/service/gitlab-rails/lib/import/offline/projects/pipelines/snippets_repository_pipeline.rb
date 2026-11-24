# frozen_string_literal: true

module Import
  module Offline
    module Projects
      module Pipelines
        class SnippetsRepositoryPipeline
          include ::BulkImports::Pipeline
          include ::BulkImports::Pipeline::IndexCacheStrategy

          SnippetRepositoryError = Class.new(StandardError)

          file_extraction_pipeline!
          relation_name ::BulkImports::FileTransfer::ProjectConfig::SNIPPET_REPOSITORIES_RELATION

          def extract(_context)
            download_service.execute
            decompression_service.execute
            extraction_service.execute

            # Preload the shard here because #load resolves repository_storage per snippet, which would otherwise N+1.
            ::BulkImports::Pipeline::ExtractedData.new(data: portable.snippets.preload_repository_shard.find_each)
          end

          # Raises rather than returns on failure so the Runner records a BulkImports::Failure for the snippet.
          def load(context, snippet)
            bundle_path = bundle_path_for(snippet)

            Gitlab::PathTraversal.check_path_traversal!(bundle_path)
            Gitlab::PathTraversal.check_allowed_absolute_path!(bundle_path, [Dir.tmpdir])

            if ambiguous_bundle_filenames.include?(File.basename(bundle_path))
              raise SnippetRepositoryError,
                'Snippet repository skipped: another snippet in the project has the same title and creation time'
            end

            return log_missing_bundle(snippet) unless File.exist?(bundle_path)

            if File.directory?(bundle_path) || Gitlab::Utils::FileInfo.linked?(bundle_path)
              raise SnippetRepositoryError, 'Snippet repository bundle is not a regular file'
            end

            # Guarded so a retried job does not fail on Gitaly's AlreadyExists
            snippet.repository.create_from_bundle(bundle_path) unless snippet.repository_exists?
            snippet.track_snippet_repository(snippet.repository.storage)

            response = Snippets::RepositoryValidationService.new(context.current_user, snippet).execute

            if response.error?
              cleanup_snippet_repository(snippet)
              raise SnippetRepositoryError, response.message
            end

            Snippets::UpdateStatisticsService.new(snippet).execute
          end

          def after_run(_)
            FileUtils.rm_rf(tmpdir)
          end

          private

          def bundle_path_for(snippet)
            File.join(tmpdir, ::Import::Offline::SnippetRepositoryBundle.filename_for(snippet))
          end

          def ambiguous_bundle_filenames
            @ambiguous_bundle_filenames ||= ::Import::Offline::SnippetRepositoryBundle.ambiguous_filenames(portable)
          end

          # Empty source repositories are never bundled, so a missing bundle is expected
          def log_missing_bundle(snippet)
            info(message: 'Snippet repository bundle not found, skipping', snippet_id: snippet.id)
          end

          def cleanup_snippet_repository(snippet)
            snippet.repository.remove
            snippet.snippet_repository.delete
            snippet.repository.expire_exists_cache
          end

          def tar_filename
            "#{self.class.relation}.tar"
          end

          def targz_filename
            "#{tar_filename}.gz"
          end

          def download_service
            ::BulkImports::FileDownloadService.for_context(
              context: context,
              relation: self.class.relation,
              tmpdir: tmpdir,
              filename: targz_filename
            )
          end

          def decompression_service
            ::BulkImports::FileDecompressionService.new(tmpdir: tmpdir, filename: targz_filename, context: context)
          end

          def extraction_service
            ::BulkImports::ArchiveExtractionService.new(tmpdir: tmpdir, filename: tar_filename)
          end

          def tmpdir
            @tmpdir ||= Dir.mktmpdir('bulk_imports')
          end
        end
      end
    end
  end
end
