# frozen_string_literal: true

namespace :gitlab do
  namespace :semantic_search do
    namespace :code do
      desc 'GitLab | Semantic Code Search | List information about Semantic Code Search integration'
      task :info, [:watch_interval] => :gitlab_environment do |t, args|
        Search::RakeTask::SemanticSearch.info(
          name: t.name,
          watch_interval: args[:watch_interval]
        )
      end
    end

    desc 'GitLab | Semantic Search | Set up the connection, migrations, and feature flags'
    task setup: :gitlab_environment do
      Search::RakeTask::SemanticSearchDevSetup.setup
    end

    namespace :setup do
      desc 'GitLab | Semantic Search | Index a project and generate its embeddings'
      task :index_project, [:project_path] => :gitlab_environment do |_t, args|
        Search::RakeTask::SemanticSearchDevSetup.index_project(project_path: args[:project_path])
      end
    end
  end
end
