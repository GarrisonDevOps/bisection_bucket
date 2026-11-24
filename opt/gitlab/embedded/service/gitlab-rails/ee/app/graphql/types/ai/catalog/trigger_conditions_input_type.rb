# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class TriggerConditionsInputType < BaseInputObject
        graphql_name 'AiCatalogTriggerConditionsInput'
        description 'Conditions for AI Catalog triggers.'

        # A security_policy trigger is set by the system and has no conditions.
        ::Ai::FlowTrigger::EVENT_TYPES.except(:security_policy).each_key do |event_type|
          # scheduled is experimental in case it gets renamed or redesigned.
          argument event_type, ::Types::Ai::Catalog::TriggerConditionsGroupInputType,
            required: false,
            description: "Trigger condition rules for the #{event_type} event.",
            experiment: event_type == :scheduled ? { milestone: '19.4' } : nil
        end
      end
    end
  end
end
