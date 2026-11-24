# frozen_string_literal: true

module Gitlab
  module SidekiqMiddleware
    module WorkerContext
      class Client
        include Gitlab::SidekiqMiddleware::WorkerContext

        # Keys that place a job in its call chain. A job pushed again, like a retried, scheduled
        # or deferred job, already carries them and keeps them.
        CHAIN_KEYS = [
          Labkit::Context.log_key(:root_started_at),
          Labkit::Context.log_key(:correlation_depth)
        ].freeze

        def call(worker_class_or_name, job, _queue, _redis_pool, &block)
          worker_class = find_worker(worker_class_or_name.to_s.safe_constantize, job)

          # This is not a worker we know about, perhaps from a gem
          return yield unless worker_class
          return yield unless worker_class.respond_to?(:context_for_arguments)

          context_for_args = worker_class.context_for_arguments(job['args'])

          wrap_in_optional_context(context_for_args) do
            # This should be inside the context for the arguments so
            # that we don't override the feature category on the worker
            # with the one from the caller.

            root_caller_id = Gitlab::ApplicationContext.current_context_attribute(:root_caller_id) ||
              Gitlab::ApplicationContext.current_context_attribute(:caller_id)

            context = {
              root_caller_id: root_caller_id
            }

            if Feature.enabled?(:log_correlation_duration, :instance, type: :gitlab_com_derisk)
              context[:root_started_at] = root_started_at(job)
              context[:correlation_depth] = correlation_depth(job)
            else
              # Jobs enqueued before the flag was disabled still carry the keys. Drop them from the
              # job and the context, so a job pushed again and its children stop logging both fields.
              CHAIN_KEYS.each { |key| job.delete(key) }
              context[:root_started_at] = nil
              context[:correlation_depth] = nil
            end

            # We do not want to set anything explicitly in the context
            # when the feature category is 'not_owned'.
            unless worker_class.feature_category_not_owned?
              context[:feature_category] = worker_class.get_feature_category.to_s
            end

            Gitlab::ApplicationContext.with_context(**context, &block)
          end
        end

        private

        # A retried or scheduled job is pushed again and already carries the start of its chain.
        # Otherwise it comes from the enqueuing job's context, from the request start, or, for
        # a job enqueued elsewhere like a cron job, from now.
        def root_started_at(job)
          ::Gitlab::InstrumentationHelper.root_started_at_for_job(job) ||
            Gitlab::ApplicationContext.current_context_attribute(:root_started_at) ||
            Gitlab::RequestContext.instance.request_start_time ||
            Time.now.utc.to_f
        end

        # A job pushed again keeps its depth. Otherwise a job enqueued by a request, or outside
        # one, is the first job of its chain, and a job enqueued by another job is one deeper.
        def correlation_depth(job)
          ::Gitlab::InstrumentationHelper.correlation_depth_for_job(job) ||
            (Gitlab::ApplicationContext.current_context_attribute(:correlation_depth).to_i + 1)
        end
      end
    end
  end
end
