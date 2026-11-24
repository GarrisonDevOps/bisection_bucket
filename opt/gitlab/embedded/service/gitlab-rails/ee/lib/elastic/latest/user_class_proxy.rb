# frozen_string_literal: true

module Elastic
  module Latest
    class UserClassProxy < ApplicationClassProxy
      def elastic_search(query, options: {})
        query_hash = ::Search::Elastic::UserQueryBuilder.build(query: query, options: options)

        search(query_hash, options)
      end
    end
  end
end
