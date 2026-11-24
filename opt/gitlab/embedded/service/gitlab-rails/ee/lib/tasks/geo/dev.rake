# frozen_string_literal: true

namespace :geo do
  namespace :dev do
    desc 'GitLab | Geo | Dev | Add Ssf metrics to geo_node_status.json'
    task ssf_metrics: :environment do
      Rake::Task['gitlab:geo:dev:ssf_metrics'].invoke
    end
  end
end
