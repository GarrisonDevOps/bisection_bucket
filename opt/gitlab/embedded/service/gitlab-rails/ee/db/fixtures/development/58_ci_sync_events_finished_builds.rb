# frozen_string_literal: true

# Seeds the finished build sync event table, which is empty in the upgrade stop dump, so migrations
# touching it were never exercised by db:migrate:multi-version-upgrade.
#
# The dev fixtures job sorts CE and EE fixtures together, so the name has to sort after
# `58_ci_sync_events_and_deployments.rb`, which creates the finished build when the job has none.
Gitlab::Seeder.quiet do
  puts "\nGenerating CI finished build sync event data"

  build = Ci::Build.where.not(finished_at: nil).order(:id).first

  next warn "\nSkipping finished build sync event seeds: no finished build available" unless build

  # The upsert only dedupes within one partition, and the sliding list strategy moves the column
  # default on to the next one, so the guard spans partitions while the model owns the write.
  next if Ci::FinishedBuildChSyncEvent.exists?(build_id: build.id)

  Ci::FinishedBuildChSyncEvent.upsert_from_build(build)
  print '.'
end
