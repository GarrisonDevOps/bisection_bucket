# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class RepositoryIndexService
        BATCH_LIMIT = 1000

        def self.enqueue_pending_jobs
          enqueue_jobs(::Ai::ActiveContext::Code::Repository.pending, RepositoryIndexWorker)
        end

        def self.enqueue_retry_jobs
          enqueue_jobs(::Ai::ActiveContext::Code::Repository.pending_retry, RepositoryIndexWorker)
        end

        def self.enqueue_pending_deletion_jobs
          enqueue_jobs(::Ai::ActiveContext::Code::Repository.pending_deletion, RepositoryDeleteWorker)
        end

        def self.enqueue_jobs(relation, worker)
          relation.with_active_connection.limit(BATCH_LIMIT).each do |repository|
            worker.perform_async(repository.id)
          end
        end
        private_class_method :enqueue_jobs
      end
    end
  end
end
