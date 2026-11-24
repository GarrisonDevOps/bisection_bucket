# frozen_string_literal: true

require 'request_store'
require 'active_support'
require 'active_support/core_ext/module/delegation'
require 'active_support/core_ext/object/blank'
require 'active_support/core_ext/string/inflections'

require 'gitlab/experiment/errors'
require 'gitlab/experiment/base_interface'
require 'gitlab/experiment/cache'
require 'gitlab/experiment/callbacks'
require 'gitlab/experiment/rollout'
require 'gitlab/experiment/configuration'
require 'gitlab/experiment/cookies'
require 'gitlab/experiment/force_assignment'
require 'gitlab/experiment/context'
require 'gitlab/experiment/dsl'
require 'gitlab/experiment/middleware'
require 'gitlab/experiment/nestable'
require 'gitlab/experiment/variant'
require 'gitlab/experiment/version'
require 'gitlab/experiment/engine' if defined?(Rails::Engine)

module Gitlab
  class Experiment
    include BaseInterface
    include Cache
    include Callbacks
    include ForceAssignment
    include Nestable

    class << self
      # Class level behavior registration methods.

      def control(*filter_list, **options, &)
        variant(:control, *filter_list, **options, &)
      end

      def candidate(*filter_list, **options, &)
        variant(:candidate, *filter_list, **options, &)
      end

      def variant(variant, *filter_list, **options, &)
        build_behavior_callback(filter_list, variant, **options, &)
      end

      # Class level callback registration methods.

      def exclude(*filter_list, **options, &block)
        build_exclude_callback(filter_list.unshift(block), **options)
      end

      def segment(*filter_list, variant:, **options, &block)
        build_segment_callback(filter_list.unshift(block), variant, **options)
      end

      def before_run(*filter_list, **options, &block)
        build_run_callback(filter_list.unshift(:before, block), **options)
      end

      def around_run(*filter_list, **options, &block)
        build_run_callback(filter_list.unshift(:around, block), **options)
      end

      def after_run(*filter_list, **options, &block)
        build_run_callback(filter_list.unshift(:after, block), **options)
      end

      # Class level definition methods.

      def default_rollout(rollout = nil, options = {})
        return @_rollout ||= Configuration.default_rollout if rollout.blank?

        @_rollout = Rollout.resolve(rollout, options)
      end

      # Class level accessor methods.

      def published_experiments
        RequestStore.store[:published_gitlab_experiments] || {}
      end
    end

    def name
      [Configuration.name_prefix, @_name].compact.join('_')
    end

    def control(&)
      variant(:control, &)
    end

    def candidate(&)
      variant(:candidate, &)
    end

    def variant(name, &block)
      raise ArgumentError, 'name required' if name.blank?
      raise ArgumentError, 'block required' unless block.present?

      behaviors[name] = block
    end

    def context(value = nil)
      return @_context if value.blank?

      @_context.value(value)
      @_context
    end

    def assigned(value = nil)
      # Skip force assignment if a variant was already set (e.g., via constructor or explicit #assigned call).
      value ||= forced_variant_name unless @_assigned_variant_name
      @_assigned_variant_name = cache_variant(value) if value.present?
      return Variant.new(name: @_assigned_variant_name || :unresolved) if @_assigned_variant_name || @_resolving_variant

      if enabled?
        @_resolving_variant = true
        @_assigned_variant_name = cached_variant_resolver(@_assigned_variant_name)
      end

      run_callbacks(segmentation_callback_chain) do
        @_assigned_variant_name ||= :control
        Variant.new(name: @_assigned_variant_name)
      end
    ensure
      @_resolving_variant = false
    end

    def rollout(rollout = nil, options = {})
      return @_rollout ||= self.class.default_rollout(nil, options).for(self) if rollout.blank?

      @_rollout = Rollout.resolve(rollout, options).for(self)
    end

    def exclude!
      @_excluded = true
    end

    def run(variant_name = nil)
      return @_result if context.frozen?

      @_result = run_callbacks(run_callback_chain) { super(assigned(variant_name).name) }
    end

    def publish(result = nil)
      instance_exec(result, &Configuration.publishing_behavior)

      (RequestStore.store[:published_gitlab_experiments] ||= {})[name] = signature.merge(excluded: excluded?)
    end

    def track(action, **event_args)
      return unless should_track?

      instance_exec(action, tracking_context(event_args).try(:compact) || {}, &Configuration.tracking_behavior)
    end

    def enabled?
      rollout.enabled?
    end

    def excluded?
      return @_excluded if defined?(@_excluded)

      @_excluded = !run_callbacks(exclusion_callback_chain) { :not_excluded } || only_assigned?
    end

    def only_assigned?
      return false unless context.only_assigned

      find_variant.blank?
    end

    def should_track?
      enabled? && context.trackable? && !excluded?
    end

    def signature
      { variant: assigned.name.to_s, experiment: name }.merge(context.signature)
    end

    def behaviors
      @_behaviors ||= registered_behavior_callbacks
    end

    protected

    def identify(object)
      (object.respond_to?(:to_global_id) ? object.to_global_id : object).to_s
    end

    def cached_variant_resolver(provided_variant)
      return :control if excluded?

      result = cache_variant(provided_variant) { resolve_variant_name }
      result.to_sym if result.present?
    end

    def resolve_variant_name
      rollout.resolve
    end

    def tracking_context(event_args)
      {}.merge(event_args)
    end
  end
end
