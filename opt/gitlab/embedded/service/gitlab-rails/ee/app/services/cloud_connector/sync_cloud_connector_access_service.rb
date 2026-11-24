# frozen_string_literal: true

# Service to synchronize JWT Service AccessToken issued by CustomersDot application and Cloud Connector services data
module CloudConnector
  class SyncCloudConnectorAccessService
    include ActiveModel::Validations

    validate :validate_license

    def initialize(license)
      @license = license
    end

    def execute
      return error_response(errors.full_messages.join(", ")) unless valid?

      response = client.get_cloud_connector_access_data(license_key)

      return error_response(response[:errors].join(", ")) unless response[:success]

      token_storage_response = ServiceAccessTokensStorageService.new(response[:token], response[:expires_at]).execute

      catalog = response[:catalog]
      access_data_storage_response =
        ::CloudConnector::AccessCatalogStorageService.new(catalog: catalog).execute

      error_responses = [token_storage_response, access_data_storage_response].filter(&:error?)
      error_message = error_responses.filter_map { |r| r[:message] }.join(", ")
      error_responses.blank? ? ServiceResponse.success : error_response(error_message)
    end

    private

    attr_reader :license

    def client
      Gitlab::SubscriptionPortal::Client
    end

    def validate_license
      if license
        errors.add(:license, 'is not an online cloud license') unless license.online_cloud_license?
        errors.add(:license, 'grace period has been expired') if license.grace_period_expired?
        errors.add(:license, 'has no expiration date') unless license.expires_at
      else
        errors.add(:license, 'not found')
      end
    end

    def license_key
      license&.data
    end

    def error_response(message)
      ServiceResponse.error(message: message)
    end
  end
end
