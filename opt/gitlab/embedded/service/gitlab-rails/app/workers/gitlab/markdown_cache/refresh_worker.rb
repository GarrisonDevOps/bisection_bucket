# frozen_string_literal: true

module Gitlab
  module MarkdownCache
    class RefreshWorker # rubocop:disable Sidekiq/EnforceDatabaseHealthSignalDeferral -- picks up work that would otherwise be done synchronously
      # Deferring increases load on web instance CPU (since they have to re-render affected rows on
      # every load until the job gets to run), for almost no benefit: these jobs are ~0.2% of the
      # primary's writes, and disabling the FF means they're run *in* the web requests instead.

      include ApplicationWorker

      data_consistency :delayed
      feature_category :markdown
      urgency :low
      worker_resource_boundary :cpu
      loggable_arguments 0, 1

      deduplicate :until_executing
      idempotent!

      concurrency_limit -> { 100 }

      def perform(class_name, ids)
        klass = class_name.safe_constantize
        return unless klass

        failures = []

        klass.primary_key_in(Array(ids)).each do |record|
          record.refresh_markdown_cache! unless record.markdown_cache_current?
        rescue StandardError => e
          failures << [e, record.id]
        end

        return if failures.empty?

        failures.drop(1).each { |error, id| Gitlab::ErrorTracking.track_exception(error, class_name: class_name, id: id) }

        raise failures.first.first
      end
    end
  end
end
