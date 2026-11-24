# frozen_string_literal: true

# Seeds the value stream setting table, which is empty in the upgrade stop dump, so migrations
# touching it were never exercised by db:migrate:multi-version-upgrade.
Gitlab::Seeder.quiet do
  puts "\nGenerating value stream setting data"

  value_stream = Analytics::CycleAnalytics::ValueStream.order(:id).first

  next warn "\nSkipping value stream setting seeds: no value stream available" unless value_stream
  next if Analytics::CycleAnalytics::ValueStreamSetting.exists?(value_stream_id: value_stream.id)

  # `project_ids_filter_at_group_level` rejects the filter on a project level value stream, so it
  # is only populated where the stream is a group one, with a project from that group.
  project_ids = if value_stream.at_group_level?
                  Project.where(namespace_id: value_stream.group_id).order(:id).limit(1).pluck(:id)
                else
                  []
                end

  Analytics::CycleAnalytics::ValueStreamSetting.create!(
    value_stream: value_stream, namespace_id: value_stream.group_id,
    project_ids_filter: project_ids)
  print '.'
end
