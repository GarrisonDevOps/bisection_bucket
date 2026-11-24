# frozen_string_literal: true

module AuditEvents
  class BaseDestinationValidator < ActiveModel::Validator
    private

    def configs(record, category)
      destinations = if record.is_a?(AuditEvents::Group::ExternalStreamingDestination)
                       record.group.external_audit_event_streaming_destinations
                     else
                       AuditEvents::Instance::ExternalStreamingDestination.all.limit(
                         AuditEvents::ExternallyStreamable::MAXIMUM_DESTINATIONS_PER_ENTITY)
                     end

      destinations.configs_of_parent(record.id, category)
    end

    def validate_attribute_uniqueness(record, attribute_names, category)
      existing_configs = configs(record, category)

      existing_configs.each do |existing_config|
        invalid = true
        attribute_names.each do |attribute_name|
          invalid &= existing_config[attribute_name] == record.config[attribute_name]
        end

        if invalid
          record.errors.add(:config, format(_("%{attribute} already taken."), attribute: attribute_names.join(", ")))
          break
        end
      end
    end
  end
end
