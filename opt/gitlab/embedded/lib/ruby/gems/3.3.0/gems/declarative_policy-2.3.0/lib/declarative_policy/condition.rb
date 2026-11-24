# frozen_string_literal: true

module DeclarativePolicy
  # A Condition is the data structure that is created by the
  # `condition` declaration on DeclarativePolicy::Base. It is
  # more or less just a struct of the data passed to that
  # declaration. It holds on to the block to be instance_eval'd
  # on a context (instance of Base) later, via #compute.
  class Condition
    attr_reader :name, :description, :scope, :manual_score, :context_key, :key

    VALID_SCOPES = %i[user_and_subject user subject global].freeze
    ALLOWED_SCOPES = VALID_SCOPES + %i[normal]

    def initialize(name, opts = {}, &compute)
      @name = name
      @compute = compute
      @scope = fetch_scope(opts)

      @description = opts.delete(:description)
      @context_key = opts[:context_key]
      @manual_score = opts.fetch(:score, nil)
      @key = "#{@context_key}/#{@name}".freeze
    end

    def compute(context)
      !!context.instance_eval(&@compute)
    end

    private

    def fetch_scope(options)
      result = options.fetch(:scope, :user_and_subject)
      if result == :normal
        warn "[DEPRECATION] `:normal` is deprecated and will be removed in 2.0. Please use new name `:user_and_subject`"
        result = :user_and_subject
      end

      raise "Invalid scope #{result}. Allowed values: #{VALID_SCOPES.inspect}" unless ALLOWED_SCOPES.include?(result)

      result
    end
  end

  # In contrast to a Condition, a ManifestCondition contains
  # a Condition and a context object, and is capable of calculating
  # a result itself. This is the return value of Base#condition.
  class ManifestCondition
    def initialize(condition, context)
      @condition = condition
      @context = context
    end

    # The main entry point - does this condition pass? We reach into
    # the context's cache here so that we can share in the global
    # cache (often RequestStore or similar).
    def pass?
      Thread.current[:declarative_policy_current_runner_state]&.register(self)

      @context.cache(cache_key) { @condition.compute(@context) }
    end

    # Whether we've already computed this condition.
    def cached?
      @context.cached?(cache_key)
    end

    # This is used to score Rule::Condition. See Rule::Condition#score
    # and Runner#steps_by_score for how scores are used.
    #
    # The number here is intended to represent, abstractly, how
    # expensive it would be to calculate this condition.
    #
    # See #cache_key for info about @condition.scope.
    def score
      # If we've been cached, no computation is necessary.
      return 0 if cached?

      # Use the override from condition(score: ...) if present
      return @condition.manual_score if @condition.manual_score

      # Global scope rules are cheap due to max cache sharing
      return 2 if  @condition.scope == :global

      # "Normal" rules can't share caches with any other policies
      return 16 if @condition.scope == :user_and_subject

      # otherwise, we're :user or :subject scope, so it's 4 if
      # the caller has declared a preference
      return 4 if @condition.scope == DeclarativePolicy.preferred_scope

      # and 8 for all other :user or :subject scope conditions.
      8
    end

    # This method controls the caching for the condition. This is where
    # the condition(scope: ...) option comes into play. Notice that
    # depending on the scope, we may cache only by the user or only by
    # the subject, resulting in sharing across different policy objects.
    def cache_key
      @cache_key ||=
        case @condition.scope
        when :global  then "/dp/condition/#{@condition.key}"
        when :user    then "/dp/condition/#{@condition.key}/#{user_key}"
        when :subject then "/dp/condition/#{@condition.key}/#{subject_key}"
        else "/dp/condition/#{@condition.key}/#{user_key},#{subject_key}"
        end.freeze
    end

    private

    def user_key
      @context.user_cache_key
    end

    def subject_key
      @context.subject_cache_key
    end
  end
end
