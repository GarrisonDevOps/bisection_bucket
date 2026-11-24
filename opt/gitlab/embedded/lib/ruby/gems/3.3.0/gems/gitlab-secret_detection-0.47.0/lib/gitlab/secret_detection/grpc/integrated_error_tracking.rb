# frozen_string_literal: true

require 'sentry-ruby'

require_relative '../../../../lib/gitlab/secret_detection/core/ruleset'

module Gitlab
  module SecretDetection
    module GRPC
      module IntegratedErrorTracking
        extend self

        def track_exception(exception, args = {})
          unless Sentry.initialized?
            logger.warn(message: "Cannot track exception in Error Tracking as Sentry is not initialized")
            return
          end

          args[:ruleset_version] = ruleset_version

          Sentry.capture_exception(exception, **args)
        end

        def setup(logger: Logger.new($stdout))
          if Sentry.initialized?
            logger.warn(message: "Sentry is already initialized, skipping re-setup")
            return
          end

          logger.info(message: "Initializing Sentry SDK for Integrated Error Tracking..")

          unless can_setup_sentry?
            logger.warn(message: "Integrated Error Tracking not available, skipping Sentry SDK initialization")
            return false
          end

          Sentry.init do |config|
            config.dsn = ENV.fetch('SD_TRACKING_DSN')
            config.environment = ENV.fetch('SD_ENV')
            config.release = Gitlab::SecretDetection::Gem::VERSION
            config.send_default_pii = true
            config.send_modules = false
            config.traces_sample_rate = 0.2 if ENV.fetch('ENABLE_SENTRY_PERFORMANCE_MONITORING', 'false') == 'true'
          end

          Sentry.set_context('ruleset', { version: ruleset_version })

          true
        rescue StandardError => e
          logger.error(message: "Failed to initialize Sentry SDK for Integrated Error Tracking: #{e}")
          raise e
        end

        def ruleset_version
          @ruleset_version ||= Gitlab::SecretDetection::Core::Ruleset.new.extract_ruleset_version || 'unknown'
        end

        def can_setup_sentry?
          ENV.fetch('SD_ENV', '') == 'production' && ENV.fetch('SD_TRACKING_DSN', '') != ''
        end
      end
    end
  end
end
