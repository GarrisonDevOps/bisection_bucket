# frozen_string_literal: true

class PagesDomainVerificationWorker
  include ApplicationWorker
  include CronjobChildWorker

  data_consistency :always

  sidekiq_options retry: 3

  feature_category :pages

  idempotent!
  # The cron enqueues every domain every 15 minutes; a TTL over that keeps jobs held by the
  # concurrency limit deduplicated.
  deduplicate :until_executing, ttl: 2.hours
  concurrency_limit -> { 50 }

  def perform(domain_id)
    return if Gitlab::Database.read_only?

    domain = PagesDomain.find_by_id(domain_id)

    return unless domain

    VerifyPagesDomainService.new(domain).execute
  end
end
