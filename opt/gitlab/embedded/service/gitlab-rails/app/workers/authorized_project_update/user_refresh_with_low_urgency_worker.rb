# frozen_string_literal: true

module AuthorizedProjectUpdate
  class UserRefreshWithLowUrgencyWorker < ::AuthorizedProjectsWorker
    urgency :low
    queue_namespace :authorized_project_update

    concurrency_limit -> { 100 }

    idempotent!

    sidekiq_interruptions_exhausted do |job|
      schedule_safety_net_refresh(job)
    end
  end
end
