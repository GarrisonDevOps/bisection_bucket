# frozen_string_literal: true

require 'active_support/core_ext/enumerable'
require 'active_support/core_ext/object/blank'

module Gitlab
  class Experiment
    module TestBehaviors
      autoload :Trackable, 'gitlab/experiment/test_behaviors/trackable.rb'
    end

    WrappedExperiment = Struct.new(:klass, :experiment_name, :variant_name, :expectation_chain, :blocks, :assigned)

    module RSpecMocks
      @__gitlab_experiment_receivers = {}

      def self.track_gitlab_experiment_receiver(method, receiver)
        # Leverage the `>=` method on Gitlab::Experiment to determine if the receiver is an experiment, not the other
        # way round -- `receiver.<=` could be mocked and we want to be extra careful.
        (@__gitlab_experiment_receivers[method] ||= []) << receiver if Gitlab::Experiment >= receiver
      rescue StandardError # again, let's just be extra careful
        false
      end

      def self.bind_gitlab_experiment_receiver(method)
        method.unbind.bind(@__gitlab_experiment_receivers[method].pop)
      end

      module MethodDouble
        def proxy_method_invoked(receiver, *args, &)
          RSpecMocks.track_gitlab_experiment_receiver(original_method, receiver)
          super
        end
        ruby2_keywords :proxy_method_invoked if respond_to?(:ruby2_keywords, true)
      end
    end

    module RSpecHelpers
      def stub_experiments(experiments)
        experiments.each do |experiment|
          wrapped_experiment(experiment, remock: true) do |instance, wrapped|
            # Stub internal methods that will make it behave as we've instructed.
            allow(instance).to receive(:enabled?) { wrapped.variant_name != false }

            # Stub the variant resolution logic to handle true/false, and named variants.
            allow(instance).to receive(:resolve_variant_name).and_wrap_original { |method|
              # Call the original method if we specified simply `true`.
              wrapped.variant_name == true ? method.call : wrapped.variant_name
            }

            # Stub find_variant only if caching is not enabled
            unless Configuration.cache
              variant_return_value = wrapped.assigned ? wrapped.variant_name.to_s : nil
              allow(instance).to receive(:find_variant).and_return(variant_return_value)
            end
          end
        end

        wrapped_experiments
      end

      def wrapped_experiment(experiment, remock: false, &block)
        klass, experiment_name, variant_name, assigned = *extract_experiment_details(experiment)

        wrapped_experiment = wrapped_experiments[experiment_name] =
          (!remock && wrapped_experiments[experiment_name]) ||
          WrappedExperiment.new(klass, experiment_name, variant_name, wrapped_experiment_chain_for(klass), [], assigned)

        wrapped_experiment.blocks << block if block
        wrapped_experiment
      end

      private

      def wrapped_experiments
        @__wrapped_experiments ||= defined?(HashWithIndifferentAccess) ? HashWithIndifferentAccess.new : {}
      end

      def wrapped_experiment_chain_for(klass)
        @__wrapped_experiment_chains ||= {}
        @__wrapped_experiment_chains[klass.name || klass.object_id] ||= begin
          allow(klass).to receive(:new).and_wrap_original do |method, *args, **kwargs, &original_block|
            RSpecMocks.bind_gitlab_experiment_receiver(method).call(*args, **kwargs).tap do |instance|
              wrapped = @__wrapped_experiments[instance.instance_variable_get(:@_name)]
              wrapped&.blocks&.each { |b| b.call(instance, wrapped) }

              original_block&.call(instance)
            end
          end
        end
      end

      def extract_experiment_details(experiment)
        experiment_name = nil
        variant_name = nil
        assigned = nil

        if experiment.is_a?(Array)
          # From normalize_experiments: [experiment_name, variant_name_or_config]
          experiment_name, variant_name = *experiment
          assigned = variant_name.is_a?(Hash) ? variant_name.delete(:assigned) : nil
          variant_name = variant_name[:variant] if variant_name.is_a?(Hash)
        elsif experiment.is_a?(Symbol)
          experiment_name = experiment
        end

        base_klass = Configuration.base_class.constantize
        variant_name = experiment.assigned.name if experiment.is_a?(base_klass)

        resolved_klass = experiment_klass(experiment) { base_klass.constantize(experiment_name) }
        experiment_name ||= experiment.instance_variable_get(:@_name)

        [resolved_klass, experiment_name.to_s, variant_name, assigned]
      end

      def experiment_klass(experiment, &block)
        if experiment.class.name.nil? # anonymous class instance
          experiment.class
        elsif experiment.instance_of?(Class) # class level stubbing, eg. "MyExperiment"
          experiment
        elsif block
          yield
        end
      end
    end

    # Records experiment tracking calls captured via Configuration.tracking_behavior, so the
    # `have_tracked_experiment` matcher can assert on the ordered sequence of emitted events. Only
    # GLEX-native data is captured (the action plus the experiment's signature), so it works for any
    # consumer regardless of how the host application wires up tracking.
    class TrackedExperiments
      attr_reader :events

      def initialize(max_segmentations = 1)
        @events = []
        @max_segmentations = max_segmentations
      end

      def record(action, signature)
        event = { action: }.merge(signature)
        verify_single_assignment(event)
        @events << event
      end

      private

      def verify_single_assignment(event)
        return unless event[:action] == :assignment && event[:key].present?

        keys = @events.select { |e| e[:action] == :assignment && e[:key].present? }
          .pluck(:key).push(event[:key]).uniq
        return unless keys.size > @max_segmentations

        raise "#{event[:experiment]} was segmented #{keys.size} " \
          "#{keys.size == 1 ? 'time' : 'times'} (expected #{@max_segmentations}) - #{keys.join(', ')}."
      end
    end

    module RSpecMatchers
      extend RSpec::Matchers::DSL

      def require_experiment(experiment, matcher, instances_only: true)
        klass = experiment.instance_of?(Class) ? experiment : experiment.class
        raise ArgumentError, "the #{matcher} matcher is limited to experiments" unless klass <= Gitlab::Experiment

        if instances_only && experiment == klass
          raise ArgumentError, "the #{matcher} matcher is limited to experiment instances"
        end

        experiment
      end

      def tracked_experiments
        @_tracked_experiments
      end

      matcher :register_behavior do |behavior_name|
        match do |experiment|
          @experiment = require_experiment(experiment, 'register_behavior')

          block = @experiment.behaviors[behavior_name]
          @return_expected = false unless block

          if @return_expected
            @actual_return = block.call
            @expected_return == @actual_return
          else
            block
          end
        end

        chain :with do |expected|
          @return_expected = true
          @expected_return = expected
        end

        failure_message do
          add_details("expected the #{behavior_name} behavior to be registered")
        end

        failure_message_when_negated do
          add_details("expected the #{behavior_name} behavior not to be registered")
        end

        def add_details(base)
          details = []

          if @return_expected
            base = "#{base} with a return value"
            details << "    expected return: #{@expected_return.inspect}\n" \
                       "      actual return: #{@actual_return.inspect}"
          else
            details << "    behaviors: #{@experiment.behaviors.keys.inspect}"
          end

          details.unshift(base).join("\n")
        end
      end

      matcher :exclude do |context|
        match do |experiment|
          @experiment = require_experiment(experiment, 'exclude')
          @experiment.context(context)
          @experiment.instance_variable_set(:@_excluded, nil)

          !@experiment.run_callbacks(:exclusion_check) { :not_excluded }
        end

        failure_message do
          "expected #{context} to be excluded"
        end

        failure_message_when_negated do
          "expected #{context} not to be excluded"
        end
      end

      matcher :segment do |context|
        match do |experiment|
          @experiment = require_experiment(experiment, 'segment')
          @experiment.context(context)
          @experiment.instance_variable_set(:@_assigned_variant_name, nil)
          @experiment.run_callbacks(:segmentation)

          @actual_variant = @experiment.instance_variable_get(:@_assigned_variant_name)
          @expected_variant ? @actual_variant == @expected_variant : @actual_variant.present?
        end

        chain :into do |expected|
          raise ArgumentError, 'variant name must be provided' if expected.blank?

          @expected_variant = expected
        end

        failure_message do
          add_details("expected #{context} to be segmented")
        end

        failure_message_when_negated do
          add_details("expected #{context} not to be segmented")
        end

        def add_details(base)
          details = []

          if @expected_variant
            base = "#{base} into variant"
            details << "    expected variant: #{@expected_variant.inspect}\n" \
                       "      actual variant: #{@actual_variant.inspect}"
          end

          details.unshift(base).join("\n")
        end
      end

      matcher :track do |event, *event_args|
        match do |experiment|
          @experiment = require_experiment(experiment, 'track', instances_only: false)

          set_expectations(event, *event_args, negated: false)
        end

        match_when_negated do |experiment|
          @experiment = require_experiment(experiment, 'track', instances_only: false)

          set_expectations(event, *event_args, negated: true)
        end

        chain(:for) do |expected|
          raise ArgumentError, 'variant name must be provided' if expected.blank?

          @expected_variant = expected
        end

        chain(:with_context) do |expected|
          raise ArgumentError, 'context name must be provided' if expected.nil?

          @expected_context = expected
        end

        chain(:on_next_instance) { @on_next_instance = true }

        def set_expectations(event, *event_args, negated:)
          failure_message = failure_message_with_details(event, negated:)
          expectations = proc do |e|
            allow(e).to receive(:track).and_call_original

            if negated
              if @expected_variant || @expected_context
                raise ArgumentError, 'cannot specify `for` or `with_context` when negating on tracking calls'
              end

              expect(e).not_to receive(:track).with(*[event, *event_args]), failure_message
            else
              expect(e.assigned.name).to(eq(@expected_variant), failure_message) if @expected_variant
              expect(e.context.value).to(include(@expected_context), failure_message) if @expected_context
              expect(e).to receive(:track).with(*[event, *event_args]).and_call_original, failure_message
            end
          end

          return wrapped_experiment(@experiment, &expectations) if @on_next_instance || @experiment.instance_of?(Class)

          expectations.call(@experiment)
        end

        def failure_message_with_details(event, negated: false)
          add_details("expected #{@experiment.inspect} #{negated ? 'not to' : 'to'} have tracked #{event.inspect}")
        end

        def add_details(base)
          details = []

          if @expected_variant
            base = "#{base} for variant"
            details << "    expected variant: #{@expected_variant.inspect}\n" \
                       "      actual variant: #{@experiment.assigned.name.inspect})"
          end

          if @expected_context
            base = "#{base} with context"
            details << "    expected context: #{@expected_context.inspect}\n" \
                       "      actual context: #{@experiment.context.value.inspect})"
          end

          details.unshift(base).join("\n")
        end
      end

      matcher :have_tracked_experiment do |experiment_name, expectation = []|
        match do
          @experiment_name = experiment_name
          @expectation = expectation

          expectation == formatted_events
        end

        failure_message do
          "Expected to track ordered events:\n#{events_to_s(@expectation)}\n" \
            "but tracked:\n#{events_to_s(formatted_events)}"
        end

        def formatted_events
          unless tracked_experiments
            raise 'have_tracked_experiment requires the :experiment_tracking metadata tag on the example'
          end

          tracked_experiments.events
            .select { |event| event[:experiment] == @experiment_name.to_s }
            .uniq { |event| event[:action] }
            .map.with_index { |event, index| format_event(event, @expectation[index] || {}) }
        end

        # A bare expectation entry (eg. `:assignment`) asserts only the action; a Hash entry (eg.
        # `{ action: :assignment, migration_keys: [...] }`) asserts each named signature field.
        def format_event(event, expected_event)
          return event[:action] unless expected_event.is_a?(Hash)

          expected_event.keys.index_with { |key| event[key] }
        end

        def events_to_s(events)
          events.map { |event| "   #{event}" }.join(",\n")
        end
      end
    end
  end
end

RSpec.configure do |config|
  config.include Gitlab::Experiment::RSpecHelpers
  config.include Gitlab::Experiment::Dsl

  config.before(:each) do |example|
    if example.metadata[:experiment] == true || example.metadata[:type] == :experiment
      RequestStore.clear!

      if defined?(Gitlab::Experiment::TestBehaviors::TrackedStructure)
        Gitlab::Experiment::TestBehaviors::TrackedStructure.reset!
      end
    end
  end

  config.include Gitlab::Experiment::RSpecMatchers, :experiment
  config.include Gitlab::Experiment::RSpecMatchers, type: :experiment
  config.include Gitlab::Experiment::RSpecMatchers, :experiment_tracking

  # Capture experiment tracking calls at the gem's own emission seam (Configuration.tracking_behavior),
  # so `have_tracked_experiment` can assert on them without coupling to any host tracking implementation.
  # The metadata value, when numeric, sets the maximum number of segmentations allowed (defaults to 1).
  config.before(:each, :experiment_tracking) do |example|
    max_segmentations = example.metadata[:experiment_tracking]
    max_segmentations = 1 unless max_segmentations.is_a?(Numeric)
    recorder = @_tracked_experiments = Gitlab::Experiment::TrackedExperiments.new(max_segmentations)

    @_original_tracking_behavior = Gitlab::Experiment::Configuration.tracking_behavior
    Gitlab::Experiment::Configuration.tracking_behavior = lambda do |action, _args|
      # `instance_exec`'d on the experiment by `Experiment#track`, so `signature` is in scope here.
      recorder.record(action, signature)
    end
  end

  config.after(:each, :experiment_tracking) do
    Gitlab::Experiment::Configuration.tracking_behavior = @_original_tracking_behavior
  end

  config.define_derived_metadata(file_path: Regexp.new('spec/experiments/')) do |metadata|
    metadata[:type] ||= :experiment
  end

  # We need to monkeypatch rspec-mocks because there's an issue around stubbing class methods that impacts us here.
  #
  # You can find out what the outcome is of the issues I've opened on rspec-mocks, and maybe some day this won't be
  # needed.
  #
  # https://github.com/rspec/rspec-mocks/issues/1452
  # https://github.com/rspec/rspec-mocks/issues/1451 (closed)
  #
  # The other way I've considered patching this is inside gitlab-experiment itself, by adding an Anonymous class and
  # instantiating that instead of the configured base_class, and then it's less common but still possible to run into
  # the issue.
  require 'rspec/mocks/method_double'
  RSpec::Mocks::MethodDouble.prepend(Gitlab::Experiment::RSpecMocks::MethodDouble)
end
