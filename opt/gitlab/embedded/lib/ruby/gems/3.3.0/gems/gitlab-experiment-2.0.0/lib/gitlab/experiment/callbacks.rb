# frozen_string_literal: true

module Gitlab
  class Experiment
    module Callbacks
      extend ActiveSupport::Concern
      include ActiveSupport::Callbacks

      included do
        # Callbacks are listed in order of when they're executed when running an experiment.

        # Exclusion check chain:
        #
        # The :exclusion_check chain is executed when determining if the context should be excluded from the experiment.
        #
        # If any callback returns true, further chain execution is terminated, the context will be considered excluded,
        # and the control behavior will be provided.
        define_callbacks(:exclusion_check, skip_after_callbacks_if_terminated: true)

        # Segmentation chain:
        #
        # The :segmentation chain is executed when no variant has been explicitly provided, the experiment is enabled,
        # and the context hasn't been excluded.
        #
        # If the :segmentation callback chain doesn't need to be executed, the :segmentation_skipped chain will be
        # executed as the fallback.
        #
        # If any callback explicitly sets a variant, further chain execution is terminated.
        define_callbacks(:segmentation)
        define_callbacks(:segmentation_skipped)

        # Run chain:
        #
        # The :run chain is executed when the experiment is enabled, and the context hasn't been excluded.
        #
        # If the :run callback chain doesn't need to be executed, the :run_skipped chain will be executed as the
        # fallback.
        define_callbacks(:run)
        define_callbacks(:run_skipped)
      end

      class_methods do
        def registered_behavior_callbacks
          @_registered_behavior_callbacks ||= {}
        end

        private

        def build_behavior_callback(filters, variant, **options, &block)
          if registered_behavior_callbacks[variant]
            raise ExistingBehaviorError, "a behavior for the `#{variant}` variant has already been registered"
          end

          callback_behavior = "#{variant}_behavior".to_sym

          # Register a the behavior so we can define the block later.
          registered_behavior_callbacks[variant] = callback_behavior

          # Add our block or default behavior method.
          filters.push(block) if block.present?
          filters.unshift(callback_behavior) if filters.empty?

          # Define and build the callback that will set our result.
          define_callbacks(callback_behavior)
          build_callback(callback_behavior, *filters, **options) do |target, callback|
            target.instance_variable_set(:@_behavior_callback_result, callback.call(target, nil))
          end
        end

        def build_exclude_callback(filters, **options)
          build_callback(:exclusion_check, *filters, **options) do |target, callback|
            throw(:abort) if target.instance_variable_get(:@_excluded) || callback.call(target, nil) == true
          end
        end

        def build_segment_callback(filters, variant, **options)
          build_callback(:segmentation, *filters, **options) do |target, callback|
            if target.instance_variable_get(:@_assigned_variant_name).nil? && callback.call(target, nil)
              target.assigned(variant)
            end
          end
        end

        def build_run_callback(filters, **options)
          set_callback(:run, *filters.compact, **options)
        end

        def build_callback(chain, *filters, **options)
          filters = filters.compact.map do |filter|
            result_lambda = ActiveSupport::Callbacks::CallTemplate.build(filter, self).make_lambda
            ->(target) { yield(target, result_lambda) }
          end

          raise ArgumentError, 'no filters provided' if filters.empty?

          set_callback(chain, *filters, **options)
        end
      end

      private

      def exclusion_callback_chain
        :exclusion_check
      end

      def segmentation_callback_chain
        return :segmentation if @_assigned_variant_name.nil? && enabled? && !excluded?

        :segmentation_skipped
      end

      def run_callback_chain
        return :run if enabled? && !excluded?

        :run_skipped
      end

      def registered_behavior_callbacks
        self.class.registered_behavior_callbacks.transform_values do |callback_behavior|
          -> { run_callbacks(callback_behavior) { @_behavior_callback_result } }
        end
      end
    end
  end
end
