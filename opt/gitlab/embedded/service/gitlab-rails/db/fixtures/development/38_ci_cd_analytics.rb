# frozen_string_literal: true

require './ee/db/seeds/shared/dora_metrics' if Gitlab.ee?

# Usage:
#
# Simple invocation always creates a new project within a group:
#
# FILTER=ci_cd_analytics SEED_CI_CD_ANALYTICS=1 bundle exec rake db:seed_fu

# rubocop:disable Rails/Output
class Gitlab::Seeder::CiAnalytics # rubocop:disable Style/ClassAndModuleChildren
  FLAG = 'SEED_CI_CD_ANALYTICS'

  def initialize
    @project = create_new_project
  end

  def seed!
    seed_data!
  end

  private

  attr_reader :project

  def seed_data!
    Sidekiq::Worker.skipping_transaction_check do
      create_dora_metrics! if Gitlab.ee?
      create_pipelines!
      create_releases!

      puts "Successfully seeded '#{project.full_path}' for CI/CD analytics!"
      puts "URL: #{Rails.application.routes.url_helpers.project_url(project)}"
    end
  end

  def create_new_project
    organization = admin.organization

    namespace = FactoryBot.create(
      :group,
      name: "CICD analytics Group #{suffix}",
      path: "cicd-#{suffix}",
      organization: organization
    )
    project = FactoryBot.create(
      :project,
      :repository,
      name: "CICD analytics Project #{suffix}",
      path: "cicd-#{suffix}",
      creator: admin,
      namespace: namespace,
      organization: organization
    )

    namespace.add_owner(admin)
    project.create_repository
    project
  end

  def create_dora_metrics!
    Gitlab::Seeder::DoraMetrics.new(project: project).execute
  end

  def create_pipelines!
    pipeline_statuses = [:success, :failed]

    # Non-ASCII branch names first rather than sampled: the coverage check reads those names as
    # the `glyphs` class, and a sample of 15 left them out of most runs.
    multibyte, ascii = project.repository.branches.sort_by(&:name).partition do |branch|
      branch.name.bytesize != branch.name.length
    end

    (multibyte + ascii).first(15).each_with_index do |branch, index|
      FactoryBot.create(
        :ci_pipeline,
        pipeline_statuses[index % 2],
        project: project,
        ref: branch.name,
        sha: branch.target,
        created_at: (index * 8).days.ago,
        duration: (index % 10).hours
      )
    end
  end

  def create_releases!
    FactoryBot.create_list(:release, 3, project: project, author: admin)
  end

  def admin
    @admin ||= Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin
  end

  def suffix
    @suffix ||= Time.now.to_i
  end
end

Gitlab::Seeder.quiet do
  if ENV[Gitlab::Seeder::CiAnalytics::FLAG]
    Gitlab::Seeder::CiAnalytics.new.seed!
  else
    puts "Skipped. Use the `#{Gitlab::Seeder::CiAnalytics::FLAG}` environment variable to enable."
  end
end
# rubocop:enable Rails/Output
