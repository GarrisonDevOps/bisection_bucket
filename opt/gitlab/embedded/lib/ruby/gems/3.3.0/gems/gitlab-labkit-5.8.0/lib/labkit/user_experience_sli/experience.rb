# frozen_string_literal: true

require 'active_support/hash_with_indifferent_access'
require 'forwardable'
require 'labkit/context'
require 'labkit/user_experience_sli/current'
require 'labkit/user_experience_sli/error'

module Labkit
  module UserExperienceSli
    URGENCY_THRESHOLDS_IN_SECONDS = {
      sync_fast: 2,
      sync_slow: 5,
      async_fast: 15,
      async_slow: 300
    }.freeze

    RESERVED_KEYWORDS = %w[
      checkpoint
      user_experience_id
      feature_category
      urgency
      start_time
      checkpoint_time
      end_time
      elapsed_time_s
      urgency_threshold_s
      error
      error_message
      success
    ].freeze

    # The `Experience` class represents a single User Experience
    # event to be measured and reported.
    class Experience
      extend Forwardable

      attr_reader :error, :start_time

      def initialize(definition)
        @definition = definition
      end

      def id
        @definition.user_experience_id
      end

      # Rehydrate an Experience instance from serialized data.
      #
      # @param data [Hash] A hash of serialized data.
      # @return [Experience]
      def rehydrate(data = {})
        @start_time = Time.iso8601(data["start_time"]) if data&.has_key?("start_time") && data["start_time"]
        self
      rescue ArgumentError
        warn("Invalid #{id}, start_time: #{data['start_time']}")
        self
      end

      # Start the User Experience.
      #
      # @yield [self] When a block is provided, the experience will be completed automatically.
      # @param extra [Hash] Additional data to include in the log event
      # @return [self] When no block is given.
      # @return [Object] The result of the block when a block is given.
      # @raise [UserExperienceError] If the block raises an error.
      #
      # Usage:
      #
      #  UserExperience.new(definition).start do |experience|
      #    experience.checkpoint
      #    experience.checkpoint
      #  end
      #
      #  experience = UserExperience.new(definition)
      #  experience.start
      #  experience.checkpoint
      #  experience.complete
      def start(**extra, &)
        @start_time = Time.now.utc
        checkpoint_counter.increment(checkpoint: "start", **base_labels)
        log_event("start", **extra)

        Labkit::UserExperienceSli::Current.active_experiences[id] = self

        return self unless block_given?

        completable(**extra, &)
      end

      # Checkpoint the User Experience.
      #
      # @param extra [Hash] Additional data to include in the log event
      # @return [self]
      def checkpoint(**extra)
        return self unless ensure_started!

        @checkpoint_time = Time.now.utc
        checkpoint_counter.increment(checkpoint: "intermediate", **base_labels)
        log_event("intermediate", **extra)

        self
      end

      # Resume the User Experience.
      #
      # @yield [self] When a block is provided, the experience will be completed automatically.
      # @param extra [Hash] Additional data to include in the log event
      # @return [self] When no block is given.
      # @return [Object] The result of the block when a block is given.
      def resume(**extra, &)
        return self unless ensure_started!

        checkpoint(checkpoint_action: 'resume', **extra)

        return self unless block_given?

        completable(**extra, &)
      end

      # Complete the User Experience.
      #
      # @param extra [Hash] Additional data to include in the log event
      # @return [self]
      def complete(**extra)
        return self unless ensure_started! && ensure_incomplete!

        begin
          @end_time = Time.now.utc
        ensure
          checkpoint_counter.increment(checkpoint: "end", **base_labels)
          total_counter.increment(error: has_error?, **base_labels)
          apdex_counter.increment(success: apdex_success?, **base_labels) unless has_error?
          log_event("end", **extra)
          Labkit::UserExperienceSli::Current.active_experiences.delete(id)
        end

        self
      end

      # Records a past User Experience by its duration.
      #
      # @param start_time [Time] The time when the experience started.
      # @param error [Boolean] Whether the experience ended in an error.
      # @param extra [Hash] Additional data to include in the log events.
      # @return [self]
      def observed(start_time:, error: false, **extra)
        @start_time = start_time.utc
        @end_time = Time.now.utc
        error!("observed_error") if error

        checkpoint_counter.increment(checkpoint: "start", **base_labels)
        log_event("start", **extra)

        checkpoint_counter.increment(checkpoint: "end", **base_labels)
        total_counter.increment(error: has_error?, **base_labels)
        apdex_counter.increment(success: apdex_success?, **base_labels) unless has_error?
        log_event("end", **extra)

        self
      end

      # Marks the experience as failed with an error
      #
      # @param error [StandardError, String] The error that caused the experience to fail.
      # @return [self]
      def error!(error)
        @error = error
        self
      end

      def has_error?
        !!@error
      end

      def to_h
        return {} unless ensure_started!

        { id => { "start_time" => @start_time&.iso8601(3) } }
      end

      private

      def base_labels
        @base_labels ||= @definition.to_h.slice(:user_experience_id, :feature_category, :urgency)
      end

      def ensure_started!
        return @start_time unless @start_time.nil?

        warn("User Experience #{@definition.user_experience_id} not started")
        false
      end

      def completable(**extra, &)
        yield self
      rescue StandardError => e
        error!(e)
        raise
      ensure
        complete(**extra)
      end

      def ensure_incomplete!
        return true if @end_time.nil?

        warn("User Experience #{@definition.user_experience_id} already completed")
        false
      end

      def urgency_threshold
        # Definitions are loaded through the registry, which validates the schema before instantiating them.
        # The schema guarantees experience with custom urgency provide apdex_threshold_s.
        @definition.apdex_threshold_s || URGENCY_THRESHOLDS_IN_SECONDS[@definition.urgency.to_sym]
      end

      def elapsed_time
        return 0 unless @start_time

        last_time = @end_time || @checkpoint_time || @start_time
        last_time - @start_time
      end

      def apdex_success?
        elapsed_time <= urgency_threshold
      end

      def checkpoint_counter
        @checkpoint_counter ||= Labkit::Metrics::Client.counter(
          :gitlab_user_experience_checkpoint_total,
          'Total checkpoints for user experiences'
        )
      end

      def total_counter
        @total_counter ||= Labkit::Metrics::Client.counter(
          :gitlab_user_experience_total,
          'Total user experience events (success/failure)'
        )
      end

      def apdex_counter
        @apdex_counter ||= Labkit::Metrics::Client.counter(
          :gitlab_user_experience_apdex_total,
          'Total user experience apdex events'
        )
      end

      def log_event(event_type, **extra)
        validate_extra_parameters!(extra)

        log_data = build_log_data(event_type, **extra)
        logger.info(log_data)
      end

      def build_log_data(event_type, **extra)
        log_data = ActiveSupport::HashWithIndifferentAccess.new(
          checkpoint: event_type,
          user_experience_id: id,
          feature_category: @definition.feature_category,
          urgency: @definition.urgency,
          start_time: @start_time&.iso8601(3),
          checkpoint_time: @checkpoint_time&.iso8601(3),
          end_time: @end_time&.iso8601(3),
          elapsed_time_s: elapsed_time,
          urgency_threshold_s: urgency_threshold
        )
        log_data.reverse_merge!(extra) if extra

        if has_error?
          log_data[:error] = true
          log_data[:error_message] = @error.inspect
        end

        log_data.compact!

        log_data
      end

      def warn(err, **extra)
        case err
        when StandardError
          logger.warn(component: self.class.name, message: err.message, **extra)
        when String
          logger.warn(component: self.class.name, message: err, **extra)
        end
      end

      def validate_extra_parameters!(extra)
        return if extra.empty?

        reserved_keys = extra.keys.map(&:to_s) & RESERVED_KEYWORDS
        return if reserved_keys.empty?

        err = ReservedKeywordError.new("Reserved keywords found in extra parameters: #{reserved_keys.join(', ')}")

        raise(err) if %w[development test].include?(ENV['RAILS_ENV'])
      end

      def logger
        Labkit::UserExperienceSli.configuration.logger
      end
    end
  end
end
