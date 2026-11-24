# frozen_string_literal: true

module Labkit
  module Middleware
    module Sidekiq
      module Tracing
        # SidekiqCommon is a mixin for the sidekiq middleware components
        module SidekiqCommon
          def job_class(job)
            # Active Job wrapping can be found at
            # https://github.com/rails/rails/blob/v6.0.3.1/activejob/lib/active_job/queue_adapters/sidekiq_adapter.rb
            job["wrapped"].presence || job["class"].presence || "undefined"
          end

          def wrapped?(job)
            job["wrapped"].present?
          end

          def tags_from_job(job, kind)
            tags = {
              "component" => "sidekiq",
              "span.kind" => kind,
              "sidekiq.wrapped" => wrapped?(job),
              "sidekiq.queue" => job["queue"],
              "sidekiq.jid" => job["jid"],
              "sidekiq.retry" => job["retry"].to_s,
              "sidekiq.args" => job["args"]&.join(", "),
            }
            tags["sidekiq.at"] = job["at"] if job["at"]
            tags
          end
        end
      end
    end
  end
end
