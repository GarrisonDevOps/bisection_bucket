# frozen_string_literal: true

module API
  module Entities
    module Ai
      module ActiveContext
        class Connection < Grape::Entity
          expose :id, documentation: { type: 'Integer', example: 1234 }
          expose :name, documentation: { type: 'String', example: 'elastic' }
          expose :adapter_class,
            documentation: { type: 'String', example: 'ActiveContext::Databases::Elasticsearch::Adapter' }
          expose :prefix, documentation: { type: 'String', example: 'gitlab' }
          expose :active, documentation: { type: 'Boolean', example: true }
          expose :created_at, documentation: { type: 'String', example: '2023-01-01T00:00:00.000Z' }
          expose :updated_at, documentation: { type: 'String', example: '2023-01-01T00:00:00.000Z' }
        end

        class Collection < Grape::Entity
          expose :id, documentation: { type: 'Integer', example: 1 }
          expose :name, documentation: { type: 'String', example: 'gitlab_active_context_code' }
          expose :connection_id, documentation: { type: 'Integer', example: 1234 }
          expose :options, documentation: { type: 'Hash', example: { queue_shard_count: 24, queue_shard_limit: 1000 } }
          expose :created_at, documentation: { type: 'String', example: '2023-01-01T00:00:00.000Z' }
          expose :updated_at, documentation: { type: 'String', example: '2023-01-01T00:00:00.000Z' }
        end

        module Code
          class EnabledNamespace < Grape::Entity
            expose :id, documentation: { type: 'Integer', example: 1 }
            expose :namespace_id, documentation: { type: 'Integer', example: 9970 }
            expose :connection_id, documentation: { type: 'Integer', example: 1234 }
            expose :state, documentation: { type: 'String', example: 'pending' }
            expose :created_at, documentation: { type: 'String', example: '2023-01-01T00:00:00.000Z' }
            expose :updated_at, documentation: { type: 'String', example: '2023-01-01T00:00:00.000Z' }
          end
        end
      end
    end
  end
end
