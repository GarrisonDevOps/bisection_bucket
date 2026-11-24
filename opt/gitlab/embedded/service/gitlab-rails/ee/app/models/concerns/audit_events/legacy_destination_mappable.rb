# frozen_string_literal: true

module AuditEvents
  module LegacyDestinationMappable
    extend ActiveSupport::Concern

    included do
      validates :legacy_destination_ref,
        uniqueness: { scope: :category },
        allow_nil: true,
        if: :instance_level?

      validates :legacy_destination_ref,
        uniqueness: { scope: [:group_id, :category] },
        allow_nil: true,
        if: :group_level?
    end

    def instance_level?
      !!(self.class <= AuditEvents::Instance::ExternalStreamingDestination)
    end

    def group_level?
      !!(self.class <= AuditEvents::Group::ExternalStreamingDestination)
    end

    def legacy_destination
      return unless legacy_destination_ref && category

      legacy_model = if instance_level?
                       instance_legacy_models[category.to_sym]
                     else
                       group_legacy_models[category.to_sym]
                     end

      legacy_model&.find_by(id: legacy_destination_ref)
    end

    private

    def instance_legacy_models
      {
        http: AuditEvents::InstanceExternalAuditEventDestination,
        aws: AuditEvents::Instance::AmazonS3Configuration,
        gcp: AuditEvents::Instance::GoogleCloudLoggingConfiguration
      }
    end

    def group_legacy_models
      {
        http: AuditEvents::ExternalAuditEventDestination,
        aws: AuditEvents::AmazonS3Configuration,
        gcp: AuditEvents::GoogleCloudLoggingConfiguration
      }
    end
  end
end
