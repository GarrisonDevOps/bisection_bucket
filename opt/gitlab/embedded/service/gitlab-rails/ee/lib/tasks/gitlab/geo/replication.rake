# frozen_string_literal: true

namespace :gitlab do
  namespace :geo do
    namespace :replication do
      desc 'GitLab | Geo | Pause replication on this secondary site'
      task pause: :gitlab_environment do
        Geo::ReplicationToggleRequestService.new(enabled: false).execute
      end

      desc 'GitLab | Geo | Resume replication on this secondary site'
      task resume: :gitlab_environment do
        Geo::ReplicationToggleRequestService.new(enabled: true).execute
      end
    end
  end
end
