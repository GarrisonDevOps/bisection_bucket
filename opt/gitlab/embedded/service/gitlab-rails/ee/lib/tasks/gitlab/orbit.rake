# frozen_string_literal: true

namespace :gitlab do
  namespace :orbit do
    desc 'GitLab | Orbit | List information about Orbit / Knowledge Graph integration'
    task :info, [:watch_interval, :extended] => :environment do |t, args|
      Analytics::RakeTask::Orbit.info(
        name: t.name,
        extended: args[:extended],
        watch_interval: args[:watch_interval]
      )
    end
  end
end
