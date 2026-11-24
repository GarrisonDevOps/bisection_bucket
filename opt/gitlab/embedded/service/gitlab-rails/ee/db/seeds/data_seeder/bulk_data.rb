# frozen_string_literal: true

require Rails.root.join('ee/db/seeds/data_seeder/data_seeder')

class DataSeeder
  # Factories that will be excluded in the process of creating test data
  EXCLUDED_FACTORIES = %w[
    cycle_analytics_value_stream_setting
  ].freeze

  def initialize(quiet = false)
    @quiet = quiet # Allows to reduce verbosity when necessary
  end

  # @example bundle exec rake "ee:gitlab:seed:data_seeder[bulk_data.rb]"
  # @example GITLAB_LOG_LEVEL=debug bundle exec rake "ee:gitlab:seed:data_seeder[bulk_data.rb]"
  def seed
    # Prepare Gitaly projects bundle files to use in factories
    TestEnv.setup_factory_repo
    TestEnv.setup_forked_repo

    reuse_existing_organization

    seed_all_fixtures
  end

  private

  # Self-managed instances allow only one organization, see
  # Organizations::Organization#validate_single_organization_on_self_managed. The instance we seed
  # already has one, so `:common_organization` (which does find_or_create_by!(path: 'common-org'))
  # tries to create a second and fails, cascading to every factory that builds a namespace.
  # Point the factory at the existing organization instead.
  #
  # Skipped in dev/test, mirroring the validation being worked around, which also leaves the global
  # FactoryBot registry untouched under RSpec.
  def reuse_existing_organization
    return if Gitlab.dev_or_test_env?
    return unless FactoryBot.factories.registered?(:common_organization)

    # rubocop:disable Gitlab/PreventOrganizationFirst -- self-managed permits exactly one organization
    # (ADR 007), which is the very constraint being worked around here. At seed time there is no
    # project or group to infer from, so reading the sole organization is both correct and unambiguous.
    existing = Organizations::Organization.first
    # rubocop:enable Gitlab/PreventOrganizationFirst
    return unless existing

    puts "Reusing existing organization ##{existing.id} (#{existing.path}) for all factories" unless @quiet

    FactoryBot.modify do
      factory :common_organization, class: 'Organizations::Organization' do
        skip_create
        initialize_with { existing }
      end
    end
  end

  def allowed_factories
    registry = FactoryBot.factories

    disallowed_factories = EXCLUDED_FACTORIES.map { |factory_name| registry.find(factory_name) }

    registry.without(disallowed_factories)
  end

  def seed_all_fixtures
    allowed_factories.each_with_index do |factory, i|
      retries ||= 0
      # Create a new instance for each factory
      resource = FactoryBot.create(factory.name)
    rescue ActiveRecord::RecordNotUnique => e
      # Workaround for UniqueViolation, context https://gitlab.com/gitlab-org/quality/quality-engineering/team-tasks/-/issues/2354#note_1793812916
      puts "#{factory.name} failed with #{e}! Attempt##{retries}"
      sleep 1
      retry if (retries += 1) < 3
    rescue Exception => e # rubocop:disable Lint/RescueException -- catching all possible exceptions
      # We rescue exception here to make sure seeding proceeds unrelated to various unique exceptions from Factories
      puts "#{factory.name} caught exception #{e} of class #{e.class}!"
    else
      Gitlab::DataSeeder.log_resource_creation(resource)
      puts "Successfully created Factory #{factory.name}" unless @quiet
    ensure
      puts "Factory ##{i + 1}" unless @quiet
    end
  end
end
