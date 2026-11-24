# frozen_string_literal: true

module Mutations
  module Security
    module ScanProfiles
      module TriggerArguments
        extend ActiveSupport::Concern

        private

        def build_triggers(triggers, scan_type)
          triggers.map do |trigger|
            {
              trigger_type: trigger.trigger_type,
              configuration: configuration_for(trigger, scan_type)
            }
          end
        end

        def configuration_for(trigger, scan_type)
          return if trigger.configuration.nil?

          # ConfigurationInputType is a `one_of` input, so exactly one member is set here.
          scan_type_member, values = trigger.configuration.deconstruct_keys(nil).first
          validate_member!(scan_type_member, :scan_type, scan_type)
          return values.to_h unless ::Security::ScanProfiles::Configuration.trigger_scoped?(scan_type)

          trigger_configuration_for(values, trigger.trigger_type)
        end

        # Trigger-scoped scan types nest one level further: the scan-type member is itself a `one_of`
        # keyed by trigger type, and it has to name the trigger the configuration is attached to.
        def trigger_configuration_for(scan_type_values, trigger_type)
          trigger_type_member, values = scan_type_values.deconstruct_keys(nil).first
          validate_member!(trigger_type_member, :trigger_type, trigger_type)

          values.to_h
        end

        def validate_member!(member, name, expected)
          return if member.to_s == expected.to_s

          raise ::Gitlab::Graphql::Errors::ArgumentError,
            "Configuration '#{member}' does not match #{name.to_s.tr('_', ' ')} '#{expected}'"
        end
      end
    end
  end
end
