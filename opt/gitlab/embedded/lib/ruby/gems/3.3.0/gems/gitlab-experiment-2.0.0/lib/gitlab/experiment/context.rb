# frozen_string_literal: true

module Gitlab
  class Experiment
    class Context
      include Cookies

      DNT_REGEXP = /^(true|t|yes|y|1|on)$/i

      attr_reader :request, :only_assigned

      def initialize(experiment, **initial_value)
        @experiment = experiment
        @value = {}
        @migrations = { merged: [], unmerged: [] }

        value(initial_value)
      end

      def reinitialize(request)
        @signature = nil # clear memoization
        @request = request if request.respond_to?(:headers) && request.respond_to?(:cookie_jar)
      end

      def value(value = nil)
        return @value if value.nil?

        value = value.dup # dup so we don't mutate
        @only_assigned = value.delete(:only_assigned)
        reinitialize(value.delete(:request))
        key(value.delete(:sticky_to))

        @value.merge!(process_migrations(value))
      end

      def key(key = nil)
        return @key || @experiment.key_for(value) if key.nil?

        @key = @experiment.key_for(key)
      end

      def trackable?
        !(@request && @request.headers['DNT'].to_s.match?(DNT_REGEXP))
      end

      def freeze
        signature # finalize before freezing
        super
      end

      def signature
        @signature ||= { key:, migration_keys: }.compact
      end

      def method_missing(method_name, *)
        @value.include?(method_name.to_sym) ? @value[method_name.to_sym] : super
      end

      def respond_to_missing?(method_name, *)
        @value.include?(method_name.to_sym) ? true : super
      end

      private

      def process_migrations(value)
        add_unmerged_migration(value.delete(:migrated_from))
        add_merged_migration(value.delete(:migrated_with))

        migrate_cookie(value, @experiment.instance_exec(@experiment, &Configuration.cookie_name))
      end

      def add_unmerged_migration(value = {})
        @migrations[:unmerged] << value if value.is_a?(Hash)
      end

      def add_merged_migration(value = {})
        @migrations[:merged] << value if value.is_a?(Hash)
      end

      def migration_keys
        return nil if @migrations[:unmerged].empty? && @migrations[:merged].empty?

        @migrations[:unmerged].map { |m| @experiment.key_for(m) } +
          @migrations[:merged].map { |m| @experiment.key_for(@value.merge(m)) }
      end
    end
  end
end
