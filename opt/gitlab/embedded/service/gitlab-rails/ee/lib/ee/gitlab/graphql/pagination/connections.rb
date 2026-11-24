# frozen_string_literal: true

module EE
  module Gitlab
    module Graphql
      module Pagination
        module Connections
          extend ActiveSupport::Concern

          class_methods do
            extend ::Gitlab::Utils::Override

            override :use
            def use(schema)
              super

              schema.connections.add(
                ::Search::Elastic::Relation,
                ::Gitlab::Graphql::Pagination::ElasticConnection)
            end
          end
        end
      end
    end
  end
end
