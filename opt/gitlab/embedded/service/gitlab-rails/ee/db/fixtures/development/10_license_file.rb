# frozen_string_literal: true

Gitlab::Seeder.quiet do
  # Ensure ApplicationSettings record exists and has a uuid
  Gitlab::CurrentSettings.current_application_settings

  Sidekiq::Worker.skipping_transaction_check do
    Rake::Task['gitlab:license:load'].invoke('verbose')
  end
end
