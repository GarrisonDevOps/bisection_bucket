# frozen_string_literal: true

# rubocop:disable Gitlab/BoundedContexts -- Legacy namespace
module BulkImports
  module Groups
    module Pipelines
      class EpicBoardsPipeline
        include NdjsonPipeline

        relation_name 'epic_boards'

        extractor ::BulkImports::Common::Extractors::NdjsonExtractor, relation: relation
      end
    end
  end
end
# rubocop:enable Gitlab/BoundedContexts
