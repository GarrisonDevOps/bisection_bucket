# frozen_string_literal: true

# Seeds a tenant's workforce hierarchy so the read API can be exercised locally and
# query plans can be taken against a tree the size of a real customer's.
#
#   FILTER=99_workforce_hierarchy bundle exec rake db:seed_fu
#   FILTER=99_workforce_hierarchy COUNT=50000 bundle exec rake db:seed_fu
#   FILTER=99_workforce_hierarchy COUNT=50000 GROUP_ID=22 bundle exec rake db:seed_fu

class Gitlab::Seeder::WorkforceHierarchy # rubocop:disable Style/ClassAndModuleChildren -- this is a seed script
  DEFAULT_COUNT = 10_000
  # CI runs every fixture, and the seed coverage report only needs a handful of rows.
  CI_COUNT = 100
  MAX_COUNT = 50_000
  BATCH_SIZE = 5_000
  MATCHED_SHARE = 0.7
  # Spans of control: narrow at the top, wider towards the front line. This gives
  # about 8 levels at 50,000 people.
  TOP_LEVELS = 2
  TOP_SPAN = (2..4)
  SPAN = (4..10)
  RANDOM_SEED = 629_837

  def self.default_count
    ENV['CI'] ? CI_COUNT : DEFAULT_COUNT
  end

  def initialize(group, count)
    @group = group
    @count = count.clamp(1, MAX_COUNT)
    @created = 0
    @sequence = 0
    @random = Random.new(RANDOM_SEED)
  end

  def seed!
    hierarchy = Workforce::Hierarchy.find_or_create_by!(group: @group)
    # Not hierarchy.people.delete_all: a has_many delete_all nullifies the foreign key,
    # which the NOT NULL column rejects.
    Workforce::Person.in_hierarchy(hierarchy).delete_all

    @user_ids = User.active.limit((@count * MATCHED_SHARE).to_i).pluck(:id)

    level = create_level(hierarchy, [nil])
    level = create_level(hierarchy, level) while @created < @count && level.any?

    Gitlab::Seeder.log_message(
      "Seeded #{@created} people into the workforce hierarchy of #{@group.full_path}."
    )
  end

  private

  # Inserts one level of the tree, then appends each new row's own id to the ancestry path
  # it inherited from its manager. Writing root to leaf means every intermediate state is
  # already a valid tree, which is the invariant the real sync has to hold too.
  def create_level(hierarchy, parents)
    rows_for_level(hierarchy, parents).each_slice(BATCH_SIZE).flat_map do |slice|
      ids = Workforce::Person.insert_all!(slice, returning: %w[id]).rows.flatten
      people = Workforce::Person.where(id: ids)

      people.update_all('traversal_ids = traversal_ids || id')
      @created += ids.size

      people.pluck(:external_xid, :traversal_ids).map do |xid, path|
        { external_xid: xid, traversal_ids: path }
      end
    end
  end

  def rows_for_level(hierarchy, parents)
    rows = []

    parents.each do |parent|
      span_of_control(parent).times do
        return rows if @created + rows.size >= @count

        rows << person_row(hierarchy, parent)
      end
    end

    rows
  end

  def span_of_control(parent)
    return 1 if parent.nil?

    @random.rand(parent[:traversal_ids].size <= TOP_LEVELS ? TOP_SPAN : SPAN)
  end

  def person_row(hierarchy, parent)
    @sequence += 1
    now = Time.current

    {
      workforce_hierarchy_id: hierarchy.id,
      # insert_all bypasses populate_sharding_key, so the sharding key is set here.
      group_id: hierarchy.group_id,
      user_id: @user_ids.pop,
      traversal_ids: parent ? parent[:traversal_ids] : [],
      external_xid: "wd-#{@sequence}",
      manager_external_xid: parent&.fetch(:external_xid),
      full_name: "Seed Person #{@sequence}",
      created_at: now,
      updated_at: now
    }
  end
end

Gitlab::Seeder.quiet do
  # The tenant on GitLab.com is a root group.
  group = ENV['GROUP_ID'] ? Group.find(ENV['GROUP_ID']) : Group.top_level.first

  if group.nil?
    puts 'Skipped: no group to attach a workforce hierarchy to.'
  else
    # Workforce::Hierarchy rejects a subgroup, so a subgroup GROUP_ID fails on create.
    count = ENV.fetch('COUNT', Gitlab::Seeder::WorkforceHierarchy.default_count).to_i

    Gitlab::Seeder::WorkforceHierarchy.new(group, count).seed!
  end
end
