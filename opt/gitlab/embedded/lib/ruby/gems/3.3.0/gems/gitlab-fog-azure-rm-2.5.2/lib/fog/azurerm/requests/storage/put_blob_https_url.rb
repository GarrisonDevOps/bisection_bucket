module Fog
  module AzureRM
    class Storage
      # This class provides the actual implemention for service calls.
      class Real
        # Generate a pre-signed URL for create an object in an Azure blob storage
        #
        # @param container_name [String] Name of container containing blob
        # @param blob_name [String] Name of blob to get expiring url for
        # @param expires [Time] An expiry time for this url
        #
        # @return [String] - https url for blob
        #
        # @see https://docs.microsoft.com/en-us/rest/api/storageservices/put-blob
        #
        def put_blob_https_url(container_name, blob_name, expires)
          relative_path = "#{container_name}/#{blob_name}"
          params = {
            service: 'b',
            resource: 'b',
            permissions: 'c',
            expiry: expires.utc.iso8601,
            protocol: 'https'
          }
          token = signature_client(expires).generate_service_sas_token(relative_path, params)
          uri = @blob_client.generate_uri(relative_path, {}, { encode: true })
          "#{uri}?#{token}"
        end
      end

      # This class provides the mock implementation for unit tests.
      class Mock
        def put_blob_https_url(*)
          'https://mockaccount.blob.core.windows.net/test_container/test_blob?token'
        end
      end
    end
  end
end
