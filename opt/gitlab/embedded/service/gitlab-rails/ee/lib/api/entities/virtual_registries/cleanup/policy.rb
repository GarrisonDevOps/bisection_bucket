# frozen_string_literal: true

module API
  module Entities
    module VirtualRegistries
      module Cleanup
        class Policy < Grape::Entity
          expose :group_id, documentation: { type: 'Integer', format: 'int64', example: 1 }
          expose :next_run_at, documentation: { type: 'DateTime' }
          expose :last_run_at, documentation: { type: 'DateTime' }
          expose :last_run_deleted_size, documentation: { type: 'Integer', format: 'int64', example: 1024 }
          expose :last_run_deleted_entries_count, documentation: { type: 'Integer', example: 5 }
          expose :keep_n_days_after_download, documentation: { type: 'Integer', example: 30 }
          expose :status, documentation: { type: 'String' }
          expose :cadence, documentation: { type: 'Integer' }
          expose :enabled, documentation: { type: 'Boolean' }
          expose :failure_message, documentation: { type: 'String' }
          expose :last_run_detailed_metrics, documentation: { type: 'Hash' }
          expose :notify_on_success, documentation: { type: 'Boolean' }
          expose :notify_on_failure, documentation: { type: 'Boolean' }
          expose :created_at, documentation: { type: 'DateTime' }
          expose :updated_at, documentation: { type: 'DateTime' }
        end
      end
    end
  end
end
