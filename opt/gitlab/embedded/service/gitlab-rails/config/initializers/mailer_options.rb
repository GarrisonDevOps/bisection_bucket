# frozen_string_literal: true

Rails.application.config.after_initialize do
  ActionMailer::MailDeliveryJob.sidekiq_options retry: 3
  ActionMailer::MailDeliveryJob.include(WorkerAttributes)
  ActionMailer::MailDeliveryJob.data_consistency :delayed

  # ActionMailer::MailDeliveryJob is made compatible with the WorkerRouter using the DummyWorker class
  klass = Gitlab::SidekiqConfig::DEFAULT_WORKERS['ActionMailer::MailDeliveryJob'].klass

  # Assigns store once during initialisation instead of during active job enqueue
  store_name = Gitlab::SidekiqConfig::WorkerRouter.global.store(klass)
  ActionMailer::MailDeliveryJob.sidekiq_options store: store_name

  # Assigns store for JobWrapper class for accuracy of client-side metric's store label
  ActiveJob::QueueAdapters::SidekiqAdapter::JobWrapper.sidekiq_options store: store_name

  ActiveJob::QueueAdapters::SidekiqAdapter::JobWrapper.include(Gitlab::SidekiqLogging::ActiveJobLoggingExtras::Wrapper)
  ActionMailer::MailDeliveryJob.include(Gitlab::SidekiqLogging::ActiveJobLoggingExtras::Job)

  # All mails share this job class, so log which mail it sends for cost attribution.
  ActionMailer::MailDeliveryJob.before_perform do |job|
    mailer_class, mailer_method = job.arguments
    job.log_hash_metadata_on_done(mailer_class: mailer_class, mailer_method: mailer_method)
  end
end
