# frozen_string_literal: true

namespace :ee do
  namespace :gitlab do
    namespace :seed do
      # @example
      #   $ rake "ee:gitlab:seed:data_seeder[path/to/seed/file(.rb,.yml,json)]"
      desc 'Seed data using GitLab Data Seeder'
      task :data_seeder, [:file] => :environment do |_, argv|
        require Rails.root.join('ee/db/seeds/data_seeder/data_seeder')

        seed_file = Rails.root.join('ee/db/seeds/data_seeder', argv[:file])

        raise "Seed file `#{seed_file}` does not exist" unless File.exist?(seed_file)

        admin = User.admins.first
        puts "Seeding data for #{admin.name}"

        Gitlab::DataSeeder.seed(admin, seed_file.to_s)
      end
    end
  end
end
