# frozen_string_literal: true

module API
  module Entities
    module Elastic
      class IndexSetting < Grape::Entity # rubocop:disable Search/NamespacedClass -- This is an API entity, not search code
        expose :alias_name,
          documentation: {
            type: 'String',
            desc: 'Name of the Elasticsearch index alias.',
            example: 'gitlab-production'
          }

        expose :number_of_shards,
          documentation: {
            type: 'Integer',
            desc: 'Number of shards for the Elasticsearch index.',
            example: 5
          }

        expose :number_of_replicas,
          documentation: {
            type: 'Integer',
            desc: 'Number of replicas for the Elasticsearch index.',
            example: 1
          }
      end
    end
  end
end
