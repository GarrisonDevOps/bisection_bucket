module Fog
  module AzureRM
    class Storage
      # This class provides the actual implemention for service calls.
      class Real
        # Get a pre-signed URL to delete an object in Azure blob storage
        # This is to make this library compatible with CarrierWave.
        #
        # @param container_name [String] Name of container containing blob
        # @param blob_name [String] Name of blob to get expiring url for
        # @param expires [Time] An expiry time for this url
        #
        # @return [String] - https url for blob
        #
        # @see https://docs.microsoft.com/en-us/rest/api/storageservices/delete-blob
        #
        def delete_object_url(container_name, blob_name, expires)
          delete_blob_https_url(container_name, blob_name, expires)
        end
      end

      # This class provides the mock implementation for unit tests.
      class Mock
        def delete_object_url(*args)
          delete_blob_https_url(*args)
        end
      end
    end
  end
end
