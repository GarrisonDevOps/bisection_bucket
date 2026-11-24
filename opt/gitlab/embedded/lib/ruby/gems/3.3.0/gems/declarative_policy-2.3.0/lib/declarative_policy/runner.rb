# frozen_string_literal: true

require 'set'

module DeclarativePolicy
  class Runner
    class State
      def initialize
        @enabled = false
        @prevented = false
        @called = nil
      end

      def enable!
        @enabled = true
      end

      def enabled?
        @enabled
      end

      def prevent!
        @prevented = true
      end

      def prevented?
        @prevented
      end

      def pass?
        !prevented? && enabled?
      end

      def register(manifest_condition)
        called[manifest_condition.cache_key] = true
      end

      def called_conditions
        return Set.new unless @called

        Set.new(@called.keys)
      end

      def absorb(other)
        return if other.equal?(self) || other.called_any.nil?

        called.update(other.called_any)
      end

      protected

      def called_any
        @called
      end

      private

      def called
        @called ||= {}
      end
    end

    # a Runner contains a list of Steps to be run.
    attr_reader :steps

    def initialize(steps)
      @steps = steps
      @state = nil
      @score = nil
      @score_epoch = nil
    end

    # We make sure only to run any given Runner once,
    # and just continue to use the resulting @state
    # that's left behind.
    def cached?
      !!@state
    end

    # Delete the cached state - allowing this runner to be re-used if the facts have changed.
    def uncache!
      @state = nil
      DeclarativePolicy.advance_score_epoch!
    end

    # used by Rule::Ability. See #steps_by_score, and Step#score for how
    # scores are kept.
    def score
      return 0 if cached?

      epoch = DeclarativePolicy.score_epoch
      return @score if @score_epoch == epoch

      @score = compute_score
      @score_epoch = epoch
      @score
    end

    def merge_runner(other)
      Runner.new(@steps + other.steps)
    end

    def dependencies
      return Set.new unless @state

      @state.called_conditions
    end

    # The main entry point, called for making an ability decision.
    # See #run and DeclarativePolicy::Base#can?
    def pass?
      run unless cached?

      parent_state = Thread.current[:declarative_policy_current_runner_state]
      parent_state&.absorb(@state)

      @state.pass?
    end

    # see DeclarativePolicy::Base#debug
    def debug(out = $stderr)
      run(out)
    end

    private

    # A run that raises part way through leaves no state behind, so the next
    # check runs again rather than reading a half-finished decision.
    #
    # A runner counts as cached from the start of its run, which changes the
    # score of every step that depends on it, so the score epoch advances
    # when the run starts, and again when a failed run is discarded.
    def with_state
      @state = State.new
      DeclarativePolicy.advance_score_epoch!
      old_runner_state = Thread.current[:declarative_policy_current_runner_state]
      Thread.current[:declarative_policy_current_runner_state] = @state
      finished = false

      yield
      finished = true
    ensure
      Thread.current[:declarative_policy_current_runner_state] = old_runner_state
      uncache! unless finished
    end

    def compute_score
      steps.sum(&:score)
    end

    def flatten_steps!
      roots = @steps.size > RootSteps::MAX_SCANNED_STEPS ? RootSteps.new(@steps) : @steps
      @steps = @steps.flat_map { |s| s.flattened(roots) }
    end

    # The steps being flattened, for Step#flattened to tell whether a step is
    # among them. A faster stand-in for Array#include?, which compares every
    # step with Step#==. Rules and policies don't define ==, so comparing
    # them by identity gives the same answer. The index is built on first
    # use, since only `can?` rules need it.
    class RootSteps
      # Up to this many steps, scanning the array is cheaper than building
      # the index.
      MAX_SCANNED_STEPS = 8

      def initialize(steps)
        @steps = steps
        @index = nil
      end

      def include?(step)
        actions = index[step.rule]&.[](step.context)

        actions ? actions.include?(step.action) : false
      end

      private

      def index
        @index ||= @steps.each_with_object({}.compare_by_identity) do |step, by_rule|
          by_context = (by_rule[step.rule] ||= {}.compare_by_identity)
          (by_context[step.context] ||= []) << step.action
        end
      end
    end
    private_constant :RootSteps

    # This method implements the semantic of "one enable and no prevents".
    # It relies on #steps_by_score for the main loop, and updates @state
    # with the result of the step.
    def run(debug = nil)
      with_state do
        steps_by_score(!!debug) do |step, score|
          break if !debug && @state.prevented?

          passed = nil
          case step.action
          when :enable
            # we only check :enable actions if they have a chance of
            # changing the outcome - if no other rule has enabled or
            # prevented.
            unless @state.enabled? || @state.prevented?
              passed = step.pass?
              @state.enable! if passed
            end
          when :prevent
            # we only check :prevent actions if the state hasn't already
            # been prevented.
            unless @state.prevented?
              passed = step.pass?
              @state.prevent! if passed
            end
          else raise "invalid action #{step.action.inspect}"
          end

          debug << inspect_step(step, score, passed) if debug
        end
      end

      @state
    end

    # This is the core spot where all those `#score` methods matter.
    # It is critical for performance to run steps in the correct order,
    # so that we don't compute expensive conditions (potentially n times
    # if we're called on, say, a large list of users).
    #
    # In order to determine the cheapest step to run next, we rely on
    # Step#score, which returns a numerical rating of how expensive
    # it would be to calculate - the lower the better. It would be
    # easy enough to statically sort by these scores, but we can do
    # a little better - the scores are cache-aware (conditions that
    # are already in the cache have score 0), which means that running
    # a step can actually change the scores of other steps.
    #
    # So! The way we sort here involves re-scoring at every step. This
    # is by necessity quadratic, but most of the time the number of steps
    # will be low. But just in case, if the number of steps exceeds 50,
    # we fall back to a static sort.
    #
    # For each step, we yield the step object along with the computed score
    # for debugging purposes.
    def steps_by_score(debugging)
      flatten_steps!

      if @steps.size > 50
        @steps.map { |s| [s.score, s] }.sort_by { |(score, _)| score }.each do |(score, step)|
          yield step, score
        end

        return
      end

      remaining = @steps.uniq
      enablers_left = remaining.count(&:enable?)
      preventers_only = false

      loop do
        if @state.enabled?
          # Once we set this, we never need to unset it, because a single
          # prevent will stop this from being enabled
          unless preventers_only
            remaining.reject!(&:enable?)
            preventers_only = true
          end
        elsif enablers_left.zero?
          # if the permission hasn't yet been enabled and we only have
          # prevent steps left, we short-circuit the state here
          @state.prevent!
          return unless debugging
        end

        return if remaining.empty?

        lowest_index, lowest_score = cheapest_step(remaining)
        step = remaining.delete_at(lowest_index)
        enablers_left -= 1 if step.enable?

        yield step, lowest_score
      end
    end

    def cheapest_step(remaining)
      lowest_score = Float::INFINITY
      lowest_index = 0
      index = 0

      while index < remaining.size
        score = remaining[index].score

        if score < lowest_score
          lowest_score = score
          lowest_index = index
          break if score.zero?
        end

        index += 1
      end

      [lowest_index, lowest_score]
    end

    # Formatter for debugging output.
    def inspect_step(step, original_score, passed)
      symbol =
        case passed
        when true then '+'
        when false then '-'
        when nil then ' '
        end

      "#{symbol} [#{original_score.to_i}] #{step.repr}\n"
    end
  end
end
