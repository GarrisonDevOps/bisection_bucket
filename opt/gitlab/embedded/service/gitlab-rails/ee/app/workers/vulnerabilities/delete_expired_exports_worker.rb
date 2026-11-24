# frozen_string_literal: true

module Vulnerabilities
  class DeleteExpiredExportsWorker
    include ApplicationWorker
    # rubocop:disable Scalability/CronWorkerContext -- This job does not require context
    include CronjobQueue

    # rubocop:enable Scalability/CronWorkerContext

    idempotent!

    worker_resource_boundary :cpu
    data_consistency :sticky
    feature_category :dependency_management

    def perform
      Vulnerabilities::Exports::BatchDestroyService.new(exports: Vulnerabilities::Export.expired).execute
    end
  end
end
