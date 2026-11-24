# frozen_string_literal: true

module Tasks
  module Gitlab
    module Openapi
      # The API classes read settings while they load during boot, so the settings that shape the
      # docs must be in place before Rails boots. Re-runs the rake command with them pinned.
      module PinnedEnvironment
        CONFIG_PATH = File.expand_path('gitlab.yml', __dir__).freeze
        RERUN_FLAG = 'OPENAPI_PINNED_RERUN'

        def self.boot!
          # The fixed config only has these sections
          unless Rails.env.development? || Rails.env.test?
            raise 'This task can only be run in the development or test environment'
          end

          rerun unless pinned?

          Rake::Task[:environment].invoke
        end

        def self.rerun
          abort "#{RERUN_FLAG} is set but the OpenAPI environment is still not pinned" if ENV[RERUN_FLAG]

          program = File.expand_path($PROGRAM_NAME, Rake.application.original_dir)

          exec(pinned_env.merge(RERUN_FLAG => '1'), Gem.ruby, program, *ARGV)
        end

        def self.pinned_env
          simulate_saas = ENV['OPENAPI_SIMULATE_SAAS'].to_s.empty? ? 'false' : ENV['OPENAPI_SIMULATE_SAAS']

          { 'GITLAB_CONFIG' => CONFIG_PATH, 'GITLAB_SIMULATE_SAAS' => simulate_saas }
        end

        def self.pinned?
          pinned_env.all? { |key, value| ENV[key] == value }
        end
      end
    end
  end
end
