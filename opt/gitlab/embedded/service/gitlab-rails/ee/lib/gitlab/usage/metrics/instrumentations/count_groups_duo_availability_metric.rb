# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountGroupsDuoAvailabilityMetric < DatabaseMetric
          DUO_SETTINGS_VALUES = ::EE::NamespaceSetting::DUO_AVAILABILITY_VALUES

          operation :count
          relation { ::Group }
          start { ::Group.minimum(:id) }
          finish { ::Group.maximum(:id) }
          metric_options do
            {
              batch_size: 10_000
            }
          end

          def initialize(metric_definition)
            super

            return if options[:duo_settings_value].in?(DUO_SETTINGS_VALUES)

            raise ArgumentError,
              "Unknown parameters: duo_settings_value:#{options[:duo_settings_value]}"
          end

          private

          def relation
            super.joins(:namespace_settings)
            .where(namespace_settings: duo_settings_to_settings_filter(options[:duo_settings_value]))
          end

          def duo_settings_to_settings_filter(duo_settings_value)
            case duo_settings_value
            when 'always_on'
              { duo_features_enabled: true, lock_duo_features_enabled: true }
            when 'default_on'
              { duo_features_enabled: true, lock_duo_features_enabled: false }
            when 'default_off'
              { duo_features_enabled: false, lock_duo_features_enabled: false }
            when 'never_on'
              { duo_features_enabled: false, lock_duo_features_enabled: true }
            end
          end
        end
      end
    end
  end
end
