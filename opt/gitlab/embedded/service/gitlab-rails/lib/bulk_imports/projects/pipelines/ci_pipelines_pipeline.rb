# frozen_string_literal: true

module BulkImports
  module Projects
    module Pipelines
      class CiPipelinesPipeline
        include NdjsonPipeline

        relation_name 'ci_pipelines'

        extractor ::BulkImports::Common::Extractors::NdjsonExtractor, relation: relation

        def on_finish
          ::Projects::ImportExport::AfterImportCiPipelinesWorker.perform_async(context.portable.id)
        end
      end
    end
  end
end
