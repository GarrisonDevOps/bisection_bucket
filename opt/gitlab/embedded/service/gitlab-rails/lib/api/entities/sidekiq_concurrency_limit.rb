# frozen_string_literal: true

module API
  module Entities
    class SidekiqConcurrencyLimit < Grape::Entity
      expose :worker_class, documentation: { type: 'String', example: 'AuthorizedProjectsWorker' }
      expose :class_limit, documentation: {
        type: 'Integer', example: 10,
        desc: 'Explicit class limit. null when the worker has no explicit limit.'
      }
      expose :effective_limit, documentation: {
        type: 'Integer', example: 20,
        desc: 'Effective limit. Zero means unlimited. Negative values mean paused. ' \
          'null means unknown without shard context.'
      }
      expose :adaptive_limit, documentation: {
        type: 'Integer', example: 5,
        desc: 'Stored adaptive limit, or null when absent.'
      }
      expose :default_limit_requires_shard_context, documentation: { type: 'Boolean', example: false }
      expose :middleware_enabled, documentation: { type: 'Boolean', example: true }
      expose :disabled_for_worker, documentation: { type: 'Boolean', example: false }
      expose :override_limit, documentation: {
        type: 'Integer', example: 20,
        desc: 'Temporary override, or null when absent.'
      }
      expose :override_ttl, documentation: {
        type: 'Integer', example: 1800,
        desc: 'Remaining override lifetime in seconds, or null when absent.'
      }
      expose :running_jobs, documentation: { type: 'Integer', example: 8 }
      expose :deferred_jobs, documentation: { type: 'Integer', example: 1000 }
    end
  end
end
