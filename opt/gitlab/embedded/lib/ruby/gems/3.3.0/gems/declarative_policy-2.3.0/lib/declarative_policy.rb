# frozen_string_literal: true

require 'set'
require_relative 'declarative_policy/cache'
require_relative 'declarative_policy/condition'
require_relative 'declarative_policy/delegate_dsl'
require_relative 'declarative_policy/prevent_all_dsl'
require_relative 'declarative_policy/policy_dsl'
require_relative 'declarative_policy/rule_dsl'
require_relative 'declarative_policy/preferred_scope'
require_relative 'declarative_policy/rule'
require_relative 'declarative_policy/runner'
require_relative 'declarative_policy/step'
require_relative 'declarative_policy/base'
require_relative 'declarative_policy/nil_policy'
require_relative 'declarative_policy/configuration'

# DeclarativePolicy: A DSL based authorization framework
module DeclarativePolicy
  extend PreferredScope

  # Counts changes to anything a step's score depends on: a condition being
  # cached, a runner starting or being uncached, and the preferred scope.
  # Steps and runners keep their last score until this changes (see
  # Step#score). It is shared by every thread. A change made elsewhere, or an
  # update lost on a Ruby without a global lock, can only change the order of
  # checks, not their result.
  @score_epoch = 0

  class << self
    # @api private
    attr_reader :score_epoch

    # @api private
    def advance_score_epoch!
      @score_epoch += 1
    end

    def policy_for(user, subject, opts = {})
      cache = opts[:cache] || {}
      key = Cache.policy_key(user, subject)

      cache[key] ||= class_for(subject).new(user, subject, opts)
    end

    # Find the list of runners with now invalidated keys, and invalidate the runners
    def invalidate(cache, invalidated_keys)
      return unless cache&.any?
      return unless invalidated_keys&.any?

      keys = invalidated_keys.to_set

      policies = cache.select { |k, _| k.is_a?(String) && k.start_with?('/dp/policy/') }

      policies.each_value do |policy|
        policy.runners.each_value do |runner|
          runner.uncache! if keys.intersect?(runner.dependencies)
        end
      end

      invalidated_keys.each { |k| cache.delete(k) }
      advance_score_epoch!

      nil
    end

    def class_for(subject)
      return configuration.nil_policy if subject.nil?
      return configuration.named_policy(subject) if subject.is_a?(Symbol)

      subject = find_delegate(subject)

      policy_class = class_for_class(subject.class)
      raise "no policy for #{subject.class.name}" if policy_class.nil?

      policy_class
    end

    def configure(&block)
      configuration.instance_eval(&block)

      nil
    end

    # Reset configuration
    def configure!(&block)
      @configuration = DeclarativePolicy::Configuration.new
      configure(&block) if block
    end

    def policy?(subject)
      !class_for_class(subject.class).nil?
    end
    alias_method :has_policy?, :policy?

    private

    def configuration
      @configuration ||= DeclarativePolicy::Configuration.new
    end

    def class_for_class(subject_class)
      if subject_class.respond_to?(:declarative_policy_class)
        Object.const_get(subject_class.declarative_policy_class)
      else
        subject_class.ancestors.each do |klass|
          name = klass.name
          klass = policy_class(name)

          return klass if klass
        end

        nil
      end
    end

    def policy_class(name)
      clazz = configuration.policy_class(name)

      clazz if clazz && clazz < Base
    end

    def find_delegate(subject)
      seen = Set.new

      while subject.respond_to?(:declarative_policy_delegate)
        raise ArgumentError, 'circular delegations' if seen.include?(subject.object_id)

        seen << subject.object_id
        subject = subject.declarative_policy_delegate
      end

      subject
    end
  end
end
