# frozen_string_literal: true

# seed-fu runs each fixture file inside a transaction, and `gitlab:license:load` now
# enqueues a Sidekiq worker (`perform_async`), which raises when called in a transaction.
# Skip the check here, as the development fixture already does for the same task.
# This is safe because setup runs without Sidekiq, and the cron backstops it: a job that
# runs before the transaction commits finds no license and no-ops, and the nightly
# `OfflineCloudLicenseProvisionWorker` run provisions the add-ons instead.
Sidekiq::Worker.skipping_transaction_check do
  Rake::Task['gitlab:license:load'].invoke
end
