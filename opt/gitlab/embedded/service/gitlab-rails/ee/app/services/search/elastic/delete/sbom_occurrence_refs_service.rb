# frozen_string_literal: true

module Search
  module Elastic
    module Delete
      class SbomOccurrenceRefsService < BaseService
        private

        def index_name
          ::Search::Elastic::Types::Sbom::OccurrenceRef.index_name
        end
      end
    end
  end
end
