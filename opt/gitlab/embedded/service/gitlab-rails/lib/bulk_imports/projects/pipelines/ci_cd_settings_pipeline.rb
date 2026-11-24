# frozen_string_literal: true

module BulkImports # rubocop:disable Gitlab/BoundedContexts -- will be moved with all other pipelines
  module Projects
    module Pipelines
      class CiCdSettingsPipeline
        include NdjsonPipeline

        relation_name 'ci_cd_settings'

        extractor ::BulkImports::Common::Extractors::NdjsonExtractor, relation: relation
      end
    end
  end
end
