# frozen_string_literal: true

module BulkImports
  module Projects
    module Pipelines
      class VulnerabilitiesPipeline
        include NdjsonPipeline

        relation_name 'vulnerabilities'

        extractor ::BulkImports::Common::Extractors::NdjsonExtractor, relation: relation
      end
    end
  end
end
