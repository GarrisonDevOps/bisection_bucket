module Fog
  module AzureRM
    class Storage
      # This class provides the actual implemention for service calls.
      class Real
        # Get an expiring https blob url from Azure blob storage
        #
        # @param container_name [String] Name of container containing blob
        # @param blob_name [String] Name of blob to get expiring url for
        # @param expires [Time] An expiry time for this url
        #
        # @return [String] - https url for blob
        #
        # @see https://msdn.microsoft.com/en-us/library/azure/mt584140.aspx
        #
        def get_blob_https_url(container_name, blob_name, expires, options = {})
          relative_path = "#{container_name}/#{blob_name}"
          relative_path = remove_trailing_periods_from_path_segments(relative_path)
          params = {
            service: 'b',
            resource: 'b',
            permissions: 'r',
            expiry: expires.utc.iso8601,
            protocol: 'https',
            content_disposition: options[:content_disposition],
            content_type: options[:content_type]
          }
          token = signature_client(expires).generate_service_sas_token(relative_path, params)
          uri = @blob_client.generate_uri(relative_path, {}, { encode: true })
          "#{uri}?#{token}"
        end
      end

      # This class provides the mock implementation for unit tests.
      class Mock
        def get_blob_https_url(*)
          'https://mockaccount.blob.core.windows.net/test_container/test_blob?token'
        end
      end
    end
  end
end
