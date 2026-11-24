# frozen_string_literal: true

Gitlab::Seeder.quiet do
  puts "\nGenerating Geo node organization links"

  Gitlab::Seeders::Geo::NodeOrganizationLinksSeeder.new.seed!
end
