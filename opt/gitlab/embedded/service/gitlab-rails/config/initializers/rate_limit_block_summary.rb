# frozen_string_literal: true

# The rack rate limiter only runs in Puma, so only Puma workers flush block counts.
return unless Gitlab::Runtime.puma?

Gitlab::Cluster::LifecycleEvents.on_worker_start do
  task = Gitlab::BackgroundTask.new(
    Gitlab::Middleware::LabkitRackRateLimit.block_summary, name: 'rate_limit_block_summary'
  ).start

  # A graceful worker stop flushes what is left.
  Gitlab::Cluster::LifecycleEvents.on_worker_stop { task.stop }
end
