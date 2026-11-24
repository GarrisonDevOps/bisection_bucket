# frozen_string_literal: true

namespace :geo do
  namespace :replication do
    desc 'GitLab | Geo | Pause replication on this secondary site'
    task pause: :gitlab_environment do
      Rake::Task['gitlab:geo:replication:pause'].invoke
    end

    desc 'GitLab | Geo | Resume replication on this secondary site'
    task resume: :gitlab_environment do
      Rake::Task['gitlab:geo:replication:resume'].invoke
    end
  end
end
