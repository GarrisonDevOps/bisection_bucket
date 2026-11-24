# frozen_string_literal: true

Gitlab::Seeder.quiet do
  Organizations::Organization.find_each do |organization|
    ::Ai::Setting.for_organization(organization)
  end
end
