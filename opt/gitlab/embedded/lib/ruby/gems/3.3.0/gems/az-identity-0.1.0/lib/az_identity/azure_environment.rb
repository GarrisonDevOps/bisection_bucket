# frozen_string_literal: true

require_relative 'constants'

module AzIdentity
  module AzureEnvironment
    # The Microsoft Entra authority (login host) differs per cloud. On AKS with
    # workload identity, AZURE_AUTHORITY_HOST is injected with the correct value
    # and takes precedence over this fallback (see WorkloadIdentityClient).
    def authority_url(environment = AzIdentity::Constants::AZURE_CLOUD)
      case environment
      when AzIdentity::Constants::AZURE_CHINA_CLOUD
        'https://login.partner.microsoftonline.cn'
      when AzIdentity::Constants::AZURE_US_GOVERNMENT
        'https://login.microsoftonline.us'
      else
        'https://login.microsoftonline.com'
      end
    end

    # The OAuth resource/audience is the same in every cloud (only the authority
    # differs), so these intentionally ignore the environment.
    # https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-azure-active-directory
    def storage_resource(_environment = AzIdentity::Constants::AZURE_CLOUD)
      'https://storage.azure.com'
    end

    def redis_resource(_environment = AzIdentity::Constants::AZURE_CLOUD)
      'https://redis.azure.com'
    end
  end
end
