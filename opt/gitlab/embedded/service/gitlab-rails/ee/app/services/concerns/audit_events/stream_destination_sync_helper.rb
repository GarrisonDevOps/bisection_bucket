# frozen_string_literal: true

module AuditEvents
  module StreamDestinationSyncHelper
    include ::AuditEvents::HeadersSyncHelper

    CreateError = Class.new(StandardError)
    UpdateError = Class.new(StandardError)
    FilterSyncError = Class.new(StandardError)

    CATEGORY_MAPPING = {
      'http' => 'ExternalAuditEventDestination',
      'aws' => 'AmazonS3Configuration',
      'gcp' => 'GoogleCloudLoggingConfiguration'
    }.freeze

    def create_legacy_destination(stream_destination_model)
      model_class = legacy_class_for(stream_destination_model)

      ApplicationRecord.transaction do
        destination = model_class.new(
          name: stream_destination_model.name,
          stream_destination_id: stream_destination_model.id,
          **extract_legacy_attributes(stream_destination_model)
        )
        destination.namespace_id = stream_destination_model.group_id if destination.respond_to?(:group)

        destination.save!

        sync_http_destination(stream_destination_model, destination) if stream_destination_model.http?

        stream_destination_model.update_column(:legacy_destination_ref, destination.id)

        destination
      end
    rescue ActiveRecord::RecordInvalid, CreateError => e
      Gitlab::ErrorTracking.track_exception(e, audit_event_destination_model: stream_destination_model.class.name)
      nil
    end

    def update_legacy_destination(stream_destination_model)
      destination = stream_destination_model.legacy_destination

      return if destination.nil? || destination.stream_destination_id != stream_destination_model.id

      ApplicationRecord.transaction do
        destination.update!(
          name: stream_destination_model.name,
          active: stream_destination_model.active,
          **extract_legacy_attributes(stream_destination_model)
        )

        sync_http_destination(stream_destination_model, destination) if stream_destination_model.http?

        destination
      end
    rescue ActiveRecord::RecordInvalid, UpdateError => e
      Gitlab::ErrorTracking.track_exception(e, audit_event_destination_model: stream_destination_model.class.name)
      nil
    end

    private

    def legacy_class_for(model)
      base = model.instance_level? ? 'AuditEvents::Instance::' : 'AuditEvents::'
      base = 'AuditEvents::Instance' if model.instance_level? && model.category == 'http'

      "#{base}#{CATEGORY_MAPPING[model.category]}".safe_constantize
    end

    def extract_legacy_attributes(stream_destination_model)
      case stream_destination_model.category
      when 'http'
        {
          destination_url: stream_destination_model.config['url'],
          verification_token: stream_destination_model.secret_token
        }
      when 'aws'
        {
          bucket_name: stream_destination_model.config['bucketName'],
          aws_region: stream_destination_model.config['awsRegion'],
          access_key_xid: stream_destination_model.config['accessKeyXid'],
          secret_access_key: stream_destination_model.secret_token
        }
      when 'gcp'
        {
          google_project_id_name: stream_destination_model.config['googleProjectIdName'],
          log_id_name: stream_destination_model.config['logIdName'],
          client_email: stream_destination_model.config['clientEmail'],
          private_key: stream_destination_model.secret_token
        }
      end
    end
  end
end
