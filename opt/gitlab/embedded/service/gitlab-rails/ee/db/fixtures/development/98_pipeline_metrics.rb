# frozen_string_literal: true

require './spec/support/sidekiq_middleware'
require 'active_support/testing/time_helpers'

# Seeds pipeline data for use in CI/CD analytics and pipeline metrics
#
# Usage:
#
# Simple invocation always creates a new project:
#
# FILTER=pipeline_metrics SEED_PIPELINE_METRICS=1 bundle exec rake db:seed_fu
# Arguments:
# - PROJECT_ID (optional) - Project to seed pipeline data for
# - PIPELINE_COUNT (optional) - Number of pipelines to seed
# - DAYS_COUNT (optional) - Number of days to seed data across
# - START_DAY_OFFSET (optional) - Number of days to offset the start date we seed
#
# Run for an existing project
#
# FILTER=pipeline_metrics SEED_PIPELINE_METRICS=1 'PROJECT_ID'= 13 bundle exec rake db:seed_fu
#
# Seed 15 pipelines over a 30 day period, starting 45 days in the past
#
# rubocop:disable Layout/LineLength -- example use of the seed script
# FILTER=pipeline_metrics SEED_PIPELINE_METRICS=1 PIPELINE_COUNT=15 DAYS_COUNT=30 START_DAY_OFFSET=45 bundle exec rake db:seed_fu
# rubocop:enable Layout/LineLength

class Gitlab::Seeder::PipelineMetrics # rubocop:disable Style/ClassAndModuleChildren -- this is a seed script
  include ActiveSupport::Testing::TimeHelpers

  attr_reader :project, :group, :user, :pipeline_count, :days_count, :start_day_offset, :organization

  def initialize(project: nil, pipeline_count: nil, days_count: nil, start_day_offset: nil)
    @user = Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin
    @organization = @user.organization
    @project = project || create_project_with_group
    @pipeline_count = pipeline_count || 25
    @days_count = days_count || 30
    @start_day_offset = start_day_offset || 1

    @group = @project.group.root_ancestor
  end

  def seed!
    seed_pipeline_analytics

    puts "."
    puts "Successfully seeded '#{project.full_path}' project for Pipeline metrics!"
    puts "URL: #{Rails.application.routes.url_helpers.project_url(project)}"
  end

  private

  def suffix
    @suffix ||= SecureRandom.hex(6)
  end

  def create_project_with_group
    Gitlab::ExclusiveLease.skipping_transaction_check do
      group = Group.new(
        name: "Pipeline metrics Group #{suffix}",
        path: "p-metrics-group-#{suffix}",
        description: FFaker::Lorem.sentence,
        organization: organization
      )

      group.save!
      group.add_owner(user)
      group.create_namespace_settings

      # Set group traversal ids inline to avoid
      # authorization issues on next steps.
      group.update!(traversal_ids: [group.id])

      # Ensure NamespaceMirror is created
      group.sync_events.each do |event|
        ::Ci::NamespaceMirror.sync!(event)
      end

      FactoryBot.create(
        :project,
        :public,
        :repository,
        name: "Pipeline metrics Project #{suffix}",
        path: "p-metrics-project-#{suffix}",
        creator: user,
        group: group
      ).tap(&:create_repository)
    end
  end

  def seed_pipeline_analytics
    seconds_in_a_day = 60 * 60 * 24
    start_day = 1.day.ago - (seconds_in_a_day * @start_day_offset.to_i)
    date_in_past = start_day - (seconds_in_a_day * @days_count.to_i)

    # Weighted towards success/failure, push events and the master branch
    rand_status = -> { %w[success success failed failed canceled].sample }
    rand_date = -> { rand(date_in_past..start_day) }
    rand_duration = -> { 1800 + (rand(1..45) * rand(60)) }
    rand_source = -> { %w[push push web duo_workflow].sample }
    rand_ref = -> { %w[master master production].sample }
    rand_committed_time = -> { (start_day - (rand(1..12) * 3600)).strftime('%F %T') }

    @pipeline_count.to_i.times do
      started = rand_date.call
      duration = rand_duration.call
      finished = started + duration
      created = started - duration

      pipeline = ::Ci::Pipeline.create(
        project: @project,
        iid: rand(1..1_000_000),
        sha: FFaker::Crypto.sha256,
        status: rand_status.call,
        source: rand_source.call,
        ref: rand_ref.call,
        committed_at: rand_committed_time.call,
        created_at: created.strftime('%F %T'),
        started_at: started.strftime('%F %T'),
        duration: duration,
        finished_at: finished.strftime('%F %T')
      )

      pipeline.run_after_commit do
        Ci::PipelineFinishedWorker.new.perform(pipeline.id)
        Ci::ClickHouse::FinishedPipelinesSyncWorker.perform_async(0, 1)
      end

      pipeline.save!
    end
  end
end

Gitlab::Seeder.quiet do
  # Environment variable used on CI to to allow requests to ClickHouse container
  WebMock.allow_net_connect! if Rails.env.test? && ENV['DISABLE_WEBMOCK']

  unless ::Gitlab::ClickHouse.configured?
    puts "
    WARNING:
    To use this seed file, you need to make sure that ClickHouse is configured and enabled with your GDK.
    Please check `doc/development/database/clickhouse/clickhouse_within_gitlab.md` for setup instructions.
    Once you've configured the config/click_house.yml file, run the migrations:

    > bundle exec rake gitlab:clickhouse:migrate

    In a Rails console session, enable ClickHouse for analytics and the feature flags:

    Gitlab::CurrentSettings.current_application_settings.update(use_clickhouse_for_analytics: true)
    "
    break
  end

  flag = 'SEED_PIPELINE_METRICS'
  project_id = ENV['PROJECT_ID']
  pipeline_count = ENV['PIPELINE_COUNT']
  days_count = ENV['DAYS_COUNT']
  start_day_offset = ENV['START_DAY_OFFSET']

  project = Project.find(project_id) if project_id

  if ENV[flag]
    seeder = Gitlab::Seeder::PipelineMetrics.new(
      project: project,
      pipeline_count: pipeline_count,
      days_count: days_count,
      start_day_offset: start_day_offset
    )
    seeder.seed!
  else
    puts "Skipped. Use the `#{flag}` environment variable to enable."
  end
end
