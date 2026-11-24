# frozen_string_literal: true

# Seeds a group runner and a project runner, each with a tag and a runner manager. Every runner
# seeded so far is instance type, so the four `ci_runner_taggings` and `ci_runner_machines`
# partitions that only the other two runner types route to were never exercised by
# db:migrate:multi-version-upgrade.
class Gitlab::Seeder::GroupAndProjectRunners # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  TAG = 'seeded-runner-tag'

  attr_reader :group, :project

  def initialize
    @group = Group.first
    @project = Project.first
  end

  def seed!
    warn_missing_owners
    seed_runner(:group_type, groups: [group]) if group
    seed_runner(:project_type, projects: [project]) if project
  end

  private

  # Naming the absent owner keeps a run that fills one pair of partitions from reading like a run
  # that filled all four.
  def warn_missing_owners
    missing = []
    missing << 'group' if group.nil?
    missing << 'project' if project.nil?
    return if missing.empty?

    warn "\nSkipping runner seeds that need: #{missing.join(', ')}"
  end

  # The factory owns the organization, the owner join row and the manager and saves them with the
  # runner, so a failed run cannot leave a runner behind without its two partitions.
  def seed_runner(runner_type, scope_attrs)
    return if partitions_seeded?(runner_type)

    FactoryBot.create(:ci_runner, :with_runner_manager,
      runner_type: runner_type, tag_list: [TAG], **scope_attrs)
    print '.'
  end

  # The fixture exists to put a row in each partition, so a re-run checks the partitions instead
  # of looking up a seeded runner.
  def partitions_seeded?(runner_type)
    Ci::RunnerTagging.public_send(runner_type).exists? &&
      Ci::RunnerManager.public_send(runner_type).exists?
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating group and project runner data"

  Gitlab::Seeder::GroupAndProjectRunners.new.seed!
end
