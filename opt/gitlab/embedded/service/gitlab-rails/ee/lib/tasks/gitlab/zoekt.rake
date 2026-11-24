# frozen_string_literal: true

namespace :gitlab do
  namespace :zoekt do
    desc 'GitLab | Zoekt | List information about Exact Code Search integration'
    task :info, [:watch_interval, :extended] => :environment do |t, args|
      Search::RakeTask::Zoekt.info(
        name: t.name,
        extended: args[:extended],
        watch_interval: args[:watch_interval]
      )
    end

    desc 'GitLab | Zoekt | Run health checks for Exact Code Search integration'
    task :health, [:watch_interval] => :environment do |t, args|
      Search::RakeTask::Zoekt.health(
        name: t.name,
        watch_interval: args[:watch_interval]
      )
    end

    desc "GitLab | Zoekt Indexer | Install or upgrade gitlab-zoekt"
    task :install, [:dir, :repo] => :gitlab_environment do |_, args|
      unless args.dir.present?
        abort %(Please specify the directory where you want to install the indexer
Usage: rake "gitlab:zoekt:install:[/installation/dir,repo]")
      end

      args.with_defaults(repo: 'https://gitlab.com/gitlab-org/gitlab-zoekt-indexer.git')
      version = Rails.root.join('GITLAB_ZOEKT_VERSION').read.chomp
      make = Gitlab::Utils.which('gmake') || Gitlab::Utils.which('make')

      abort "Couldn't find a 'make' binary" unless make

      checkout_or_clone_version(version: version, repo: args.repo, target_dir: args.dir, clone_opts: %w[--depth 1])

      Dir.chdir(args.dir) { run_command!([make, 'build-unified']) }
    end

    desc 'GitLab | Zoekt | Enable indexing and start indexing root namespaces'
    task index: :environment do
      Search::RakeTask::Zoekt.index
    end

    desc 'GitLab | Zoekt | Disable indexing and search'
    task disable: :environment do
      Search::RakeTask::Zoekt.disable
    end

    desc 'GitLab | Zoekt | Pause indexing'
    task pause_indexing: :environment do
      Search::RakeTask::Zoekt.pause_indexing
    end

    desc 'GitLab | Zoekt | Resume indexing'
    task resume_indexing: :environment do
      Search::RakeTask::Zoekt.resume_indexing
    end

    desc 'GitLab | Zoekt | Estimate storage requirements for Exact Code Search'
    task estimate_storage: :environment do
      Search::RakeTask::Zoekt.estimate_storage
    end

    desc "GitLab | Zoekt | Reindex range of projects from ENV['ID_FROM'] to ENV['ID_TO']"
    task reindex_projects: :environment do
      Search::RakeTask::Zoekt.reindex_projects
    end

    desc 'GitLab | Zoekt | Retry indexing of failed zoekt_repository records, optionally filtered by project IDs'
    task :reindex_failed_projects, [:project_ids] => :environment do |_t, args|
      project_ids = args[:project_ids]&.split(',')&.map(&:to_i)
      Search::RakeTask::Zoekt.reindex_failed_projects(project_ids: project_ids)
    end
  end
end
