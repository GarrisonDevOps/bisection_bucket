# frozen_string_literal: true

# This initializer loads the remote_development script files and sets up hot reloading in development
# environment, allowing changes to script files to be detected without restarting the server.

if Rails.env.development?
  # Files to watch for changes - watching all script and yaml files under remote_development
  script_files = Dir.glob(
    Rails.root.join('ee/lib/remote_development/**/*.{sh,yaml,yml}').to_s
  )

  # Reload Files constants on changes to any of the .sh, .yaml, or .yml files
  file_watcher = Rails.configuration.file_watcher.new(script_files) do
    RemoteDevelopment::Files.reload_constants!
  end

  Rails.application.reloaders << file_watcher
  Rails.application.reloader.to_run { file_watcher.execute_if_updated }
end
