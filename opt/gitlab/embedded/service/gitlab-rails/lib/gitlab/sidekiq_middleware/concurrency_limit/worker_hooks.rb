# frozen_string_literal: true

module Gitlab
  module SidekiqMiddleware
    module ConcurrencyLimit
      # Calls the optional `on_concurrency_limit_deferred(args)` and `on_concurrency_limit_resumed(args)`
      # class methods of a worker, for example to keep state the job needs alive while it waits.
      module WorkerHooks
        class << self
          def deferred(worker_class, job)
            call(worker_class, :on_concurrency_limit_deferred, job)
          end

          def resumed(worker_class, job)
            call(worker_class, :on_concurrency_limit_resumed, job)
          end

          private

          # Errors are only tracked, so a hook cannot lose a deferred job or stop a resume.
          #
          # @param job [Hash] the job payload, or the buffered job; its args can still be compressed
          def call(worker_class, hook, job)
            return unless worker_class.respond_to?(hook)

            worker_class.public_send(hook, uncompressed_args(job)) # rubocop:disable GitlabSecurity/PublicSend -- hook names are fixed above
          rescue StandardError => e
            Gitlab::ErrorTracking.track_exception(e, worker_class: worker_class.name, hook: hook)
          end

          def uncompressed_args(job)
            compressor = ::Gitlab::SidekiqMiddleware::SizeLimiter::Compressor
            # The args are stored or re-enqueued after the hook runs, so a hook must not be able to change them.
            return job['args'].deep_dup unless compressor.compressed?(job)

            copy = job.slice('args', compressor::COMPRESSED_KEY, compressor::ORIGINAL_SIZE_KEY)
            compressor.decompress(copy)
            copy['args']
          end
        end
      end
    end
  end
end
