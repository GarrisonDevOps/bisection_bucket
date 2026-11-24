# frozen_string_literal: true

module Search
  module Elastic
    module Delete
      class ProjectWorkItemsService < BaseService
        private

        def index_name
          ::Search::Elastic::Types::WorkItem.index_name
        end
      end
    end
  end
end
