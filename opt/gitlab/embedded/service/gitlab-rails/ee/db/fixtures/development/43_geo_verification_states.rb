# frozen_string_literal: true

# No rescue: a table that stops seeding must fail run-dev-fixtures-ee, not
# silently lose coverage.
Gitlab::Seeder.quiet do
  puts "\nGenerating Geo verification state data"

  Gitlab::Seeders::Geo::VerificationStatesSeeder.new.seed!
end
