# frozen_string_literal: true

namespace :gitlab do
  namespace :seed do
    desc 'GitLab | Seed | Create one real Upload in each Geo upload partition'
    task :geo_uploads, [:project_full_path, :count] => :environment do |_t, args|
      full_path = args[:project_full_path]
      project = full_path ? Project.find_by_full_path(full_path) : Project.first

      unless project
        message =
          if full_path
            "Project '#{full_path}' does not exist!"
          else
            'No project found. Seed a project first, or pass a project full path.'
          end

        warn Rainbow(message).red
        exit 1
      end

      count = (args[:count] || 1).to_i

      if count < 1
        warn Rainbow("Invalid count '#{args[:count]}'; must be a positive integer.").red
        exit 1
      end

      Gitlab::Seeder.quiet do
        Gitlab::Seeders::Geo::UploadPartitions.new(project).seed!(count: count)
      end
    end
  end
end
