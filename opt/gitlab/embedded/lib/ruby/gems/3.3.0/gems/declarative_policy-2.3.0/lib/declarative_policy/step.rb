# frozen_string_literal: true

module DeclarativePolicy
  # This object represents one step in the runtime decision of whether
  # an ability is allowed. It contains a Rule and a context (instance
  # of DeclarativePolicy::Base), which contains the user, the subject,
  # and the cache. It also contains an "action", which is the symbol
  # :prevent or :enable.
  class Step
    attr_reader :context, :rule, :action

    def initialize(context, rule, action)
      @context = context
      @rule = rule
      @action = action
      @score = nil
      @score_epoch = nil
    end

    # In the flattening process, duplicate steps may be generated in the
    # same rule. This allows us to eliminate those (see Runner#steps_by_score
    # and note its use of a Set)
    def ==(other)
      @context == other.context && @rule == other.rule && @action == other.action
    end

    # In the runner, steps are sorted dynamically by score, so that
    # we are sure to compute them in close to the optimal order.
    #
    # See also Rule#score, ManifestCondition#score, and Runner#steps_by_score.
    #
    # A score only changes when the score epoch does, so it is kept until
    # then. The epoch is read before scoring, since scoring can run code that
    # advances it.
    def score
      epoch = DeclarativePolicy.score_epoch
      return @score if @score_epoch == epoch

      @score = compute_score
      @score_epoch = epoch
      @score
    end

    def with_action(action)
      Step.new(@context, @rule, action)
    end

    def enable?
      @action == :enable
    end

    def prevent?
      @action == :prevent
    end

    # This rather complex method allows us to split rules into parts so that
    # they can be sorted independently for better optimization
    def flattened(roots)
      case @rule
      when Rule::Or
        # A single `Or` step is the same as each of its elements as separate steps
        @rule.rules.flat_map { |r| Step.new(@context, r, @action).flattened(roots) }
      when Rule::Ability
        # This looks like a weird micro-optimization but it buys us quite a lot
        # in some cases. If we depend on an Ability (i.e. a `can?(...)` rule),
        # and that ability *only* has :enable actions (modulo some actions that
        # we already have taken care of), then its rules can be safely inlined.
        #
        # Steps that are already in `roots` are skipped, since they run anyway.
        # A :prevent step can only skip :prevent steps, because each :enable
        # step it inlines would turn into a :prevent. For example, with
        #
        #   rule { member }.enable :read, :write
        #   rule { can?(:read) }.prevent :write
        #
        # `enable when member` is already a step of :write, but inlining needs
        # `prevent when member`, so it must not be skipped.
        steps = @context.runner(@rule.ability).steps.reject do |s|
          roots.include?(s) && !(prevent? && s.enable?)
        end

        if steps.all?(&:enable?)
          # in the case that we are a :prevent step, each inlined step becomes
          # an independent :prevent, even though it was an :enable in its initial
          # context.
          steps.map! { |s| s.with_action(:prevent) } if prevent?

          steps.flat_map { |s| s.flattened(roots) }
        else
          [self]
        end
      else
        [self]
      end
    end

    def pass?
      @rule.pass?(@context)
    end

    def repr
      "#{@action} when #{@rule.repr} (#{@context.repr})"
    end

    private

    def compute_score
      # we slightly prefer the preventative actions
      # since they are more likely to short-circuit
      case @action
      when :prevent
        @rule.score(@context) * (7.0 / 8)
      when :enable
        @rule.score(@context)
      end
    end
  end
end
