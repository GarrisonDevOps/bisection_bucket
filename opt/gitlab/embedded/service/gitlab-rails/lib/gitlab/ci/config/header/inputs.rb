# frozen_string_literal: true

module Gitlab
  module Ci
    class Config
      module Header
        class Inputs < ::Gitlab::Config::Entry::ComposableHash
          include ::Gitlab::Config::Entry::Validatable

          MAX_INPUTS = 500

          validations do
            validates :config, type: Hash

            validate do
              if exceeds_inputs_limit? && ::Gitlab::Ci::Config::FeatureFlags.enabled?(:ci_limit_spec_inputs_count)
                errors.add(:config, "cannot declare more than #{MAX_INPUTS} inputs")
              end
            end
          end

          def compose!(deps = nil)
            super

            validate_rules! if validate_rules?
            log_inputs_count
          end

          def exceeds_inputs_limit?
            config.is_a?(Hash) && config.size > MAX_INPUTS
          end

          private

          def composable_class(_name, _config)
            Header::Input
          end

          def validate_rules?
            return false unless @entries.values.any?(&:input_rules)
            return false unless @entries.values.all?(&:valid?)

            ::Gitlab::Ci::Config::FeatureFlags.enabled?(:ci_validate_spec_input_rules)
          end

          def validate_rules!
            Inputs::Validator.new(@entries).validate!
          end

          def log_inputs_count
            return unless exceeds_inputs_limit?

            Gitlab::AppJsonLogger.info(
              Labkit::Fields::CLASS_NAME => self.class.name,
              message: 'spec:inputs declares more inputs than the limit',
              inputs_count: config.size,
              inputs_limit: MAX_INPUTS
            )
          end
        end
      end
    end
  end
end
