# frozen_string_literal: true

require 'singleton'
require 'logger'
require 'digest'

module Gitlab
  class Experiment
    class Configuration
      include Singleton

      # Prefix all experiment names with a given string value.
      # Use `nil` for no prefix.
      @name_prefix = nil

      # The logger can be used to log various details of the experiments.
      @logger = Logger.new($stdout)

      # The base class that should be instantiated for basic experiments.
      # It should be a string, so we can constantize it later.
      @base_class = 'Gitlab::Experiment'

      # Require experiments to be defined in a class, with variants registered.
      # This will disallow any anonymous experiments that are run inline
      # without previously defining a class.
      @strict_registration = false

      # The caching layer is expected to match the Rails.cache interface.
      # If no cache is provided some rollout strategies may behave differently.
      # Use `nil` for no caching.
      @cache = nil

      # The domain to use on cookies.
      #
      # When not set, it uses the current host. If you want to provide specific
      # hosts, you use `:all`, or provide an array.
      #
      # Examples:
      #   nil, :all, or ['www.gitlab.com', '.gitlab.com']
      @cookie_domain = :all

      # The cookie name for an experiment.
      @cookie_name = lambda do |experiment|
        "#{experiment.name}_id"
      end

      # Allow forced variant assignment via query parameter and cookie.
      #
      # When enabled, experiments will check for a `glex_force` query
      # parameter and a `_glex_force` cookie to override variant assignment.
      # This is intended for QA/UAT testing in staging and production.
      #
      # Defaults to false (disabled).
      @allow_forced_assignment = false

      # Mark experiment cookies as secure (HTTPS only).
      #
      # When set to true, cookies will have the secure flag set, meaning they
      # will only be sent over HTTPS connections. Defaults to true.
      #
      # Set to false in development/test environments if needed:
      #   config.secure_cookie = Rails.env.production?
      @secure_cookie = true

      # The default rollout strategy.
      #
      # The recommended default rollout strategy when not using caching would
      # be `Gitlab::Experiment::Rollout::Percent` as that will consistently
      # assign the same variant with or without caching.
      #
      # Gitlab::Experiment::Rollout::Base can be inherited to implement your
      # own rollout strategies.
      #
      # Each experiment can specify its own rollout strategy:
      #
      # class ExampleExperiment < ApplicationExperiment
      #   default_rollout :random # :percent, :round_robin, or MyCustomRollout
      # end
      #
      # Included rollout strategies:
      #   :percent, (recommended), :round_robin, or :random
      @default_rollout = Rollout.resolve(:percent)

      # Secret seed used in generating context keys.
      #
      # You'll typically want to use an environment variable or secret value
      # for this.
      #
      # Consider not using one that's shared with other systems, like Rails'
      # SECRET_KEY_BASE for instance. Generate a new secret and utilize that
      # instead.
      @context_key_secret = nil

      # Bit length used by SHA2 in generating context keys.
      #
      # Using a higher bit length would require more computation time.
      #
      # Valid bit lengths:
      #   256, 384, or 512
      @context_key_bit_length = 256

      # The default base path that the middleware (or rails engine) will be
      # mounted. The middleware enables an instrumentation url, that's similar
      # to links that can be instrumented in email campaigns.
      #
      # Use `nil` if you don't want to mount the middleware.
      #
      # Examples:
      #   '/-/experiment', '/redirect', nil
      @mount_at = nil

      # When using the middleware, links can be instrumented and redirected
      # elsewhere. This can be exploited to make a harmful url look innocuous
      # or that it's a valid url on your domain. To avoid this, you can provide
      # your own logic for what urls will be considered valid and redirected
      # to.
      #
      # Expected to return a boolean value.
      @redirect_url_validator = lambda do |_redirect_url|
        true
      end

      # Tracking behavior can be implemented to link an event to an experiment.
      #
      # This block is executed within the scope of the experiment and so can
      # access experiment methods, like `name`, `context`, and `signature`.
      @tracking_behavior = lambda do |event, args|
        # An example of using a generic logger to track events:
        Configuration.logger.info("#{self.class.name}[#{name}] #{event}: #{args.merge(signature:)}")

        # Using something like snowplow to track events (in gitlab):
        #
        # Gitlab::Tracking.event(name, event, **args.merge(
        #   context: (args[:context] || []) << SnowplowTracker::SelfDescribingJson.new(
        #     'iglu:com.gitlab/gitlab_experiment/jsonschema/0-2-0', signature
        #   )
        # ))
      end

      # Logic designed to respond when a given experiment is nested within
      # another experiment. This can be useful to identify overlaps and when a
      # code path leads to an experiment being nested within another.
      #
      # Reporting complexity can arise when one experiment changes rollout, and
      # a downstream experiment is impacted by that.
      #
      # The base_class or a custom experiment can provide a `nest_experiment`
      # method that implements its own logic that may allow certain experiments
      # to be nested within it.
      #
      # This block is executed within the scope of the experiment and so can
      # access experiment methods, like `name`, `context`, and `signature`.
      #
      # The default exception will include the where the experiment calls were
      # initiated on, so for instance:
      #
      # Gitlab::Experiment::NestingError: unable to nest level2 within level1:
      #   level1 initiated by file_name.rb:2
      #   level2 initiated by file_name.rb:3
      @nested_behavior = lambda do |nested_experiment|
        raise NestingError.new(experiment: self, nested_experiment:)
      end

      # Called at the end of every experiment run, with the result.
      #
      # You may want to track that you've assigned a variant to a given
      # context, or push the experiment into the client or publish results
      # elsewhere like into redis.
      #
      # This block is executed within the scope of the experiment and so can
      # access experiment methods, like `name`, `context`, and `signature`.
      @publishing_behavior = lambda do |_result|
        # Track the event using our own configured tracking logic.
        track(:assignment)

        # Log using our logging system, so the result (which can be large) can
        # be reviewed later if we want to.
        #
        # Lograge::Event.log(experiment: name, result: result, signature: signature)

        # Experiments that have been run during the request lifecycle can be
        # pushed to the client layer by injecting the published experiments
        # into javascript in a layout or view using something like:
        #
        # = javascript_tag(nonce: content_security_policy_nonce) do
        #   window.experiments = #{raw Gitlab::Experiment.published_experiments.to_json};
      end

      class << self
        attr_accessor(
          :name_prefix,
          :logger,
          :base_class,
          :strict_registration,
          :cache,
          :cookie_domain,
          :cookie_name,
          :secure_cookie,
          :allow_forced_assignment,
          :context_key_secret,
          :context_key_bit_length,
          :mount_at,
          :default_rollout,
          :redirect_url_validator,
          :tracking_behavior,
          :nested_behavior,
          :publishing_behavior
        )

        # Attribute method overrides.

        def default_rollout=(args) # rubocop:disable Lint/DuplicateMethods
          @default_rollout = Rollout.resolve(*args)
        end

        # Internal warning helpers.

        def deprecated(*args, version:, stack: 0)
          deprecator = deprecator(version)
          args << args.pop.to_s.gsub('{{release}}', "#{deprecator.gem_name} #{deprecator.deprecation_horizon}")
          args << caller_locations(4 + stack)

          if args.length == 2
            deprecator.warn(*args)
          else
            args[0] = "`#{args[0]}`"
            deprecator.deprecation_warning(*args)
          end
        end

        private

        def deprecator(version = VERSION)
          version = Gem::Version.new(version).bump.to_s

          @__dep_versions ||= {}
          @__dep_versions[version] ||= ActiveSupport::Deprecation.new(version, 'Gitlab::Experiment')
        end
      end
    end
  end
end
