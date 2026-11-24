# frozen_string_literal: true

module Search
  module Elastic
    module Delete
      class AllBlobsService < BaseService
        private

        def index_name
          ::Elastic::Latest::Config.index_name
        end

        def build_query
          return {} if ApplicationSetting.current_without_cache&.elasticsearch_code_scope?

          {
            query: {
              term: {
                type: 'blob'
              }
            }
          }
        end
      end
    end
  end
end
