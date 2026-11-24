# frozen_string_literal: true

require 'active_support/testing/time_helpers'

# Usage:
#
# Seeds all groups:
#
# FILTER=vsd_overview_counts bundle exec rake db:seed_fu
#
# When invoking for a single group the group id should be a top-level group:
#
# GROUP_ID=22 FILTER=vsd_overview_counts bundle exec rake db:seed_fu

class Gitlab::Seeder::ValueStreamDashboardCounts # rubocop:disable Style/ClassAndModuleChildren -- this is a seed script
  include ActiveSupport::Testing::TimeHelpers

  attr_reader :group

  def initialize(group)
    @group = group
  end

  def seed!
    3.times do |month_index|
      time = month_index.months.ago.end_of_month - 3.days

      counts_to_collect = Analytics::ValueStreamDashboard::TopLevelGroupCounterService::COUNTS_TO_COLLECT
      payload = counts_to_collect.values.flat_map do |count_config|
        count_config[:namespace_class].where('traversal_ids[1] = ?', aggregation.namespace_id).map do |namespace|
          {
            count: rand(100),
            namespace_id: namespace.id,
            recorded_at: time,
            metric: count_config[:metric]
          }
        end
      end

      unique_by = Analytics::ValueStreamDashboard::TopLevelGroupCounterService::UNIQUE_BY_CLAUSE
      Analytics::ValueStreamDashboard::Count.insert_all(payload, unique_by: unique_by)
    end
  end

  def aggregation
    @aggregation ||= begin
      Analytics::ValueStreamDashboard::Aggregation.upsert({ namespace_id: group.id, enabled: true })
      Analytics::ValueStreamDashboard::Aggregation.find(group.id)
    end
  end
end

Gitlab::Seeder.quiet do
  groups = Group.top_level
  groups = groups.id_in(ENV['GROUP_ID']) if ENV['GROUP_ID']

  groups.find_each do |group|
    seeder = Gitlab::Seeder::ValueStreamDashboardCounts.new(group)
    seeder.seed!
  end
end
