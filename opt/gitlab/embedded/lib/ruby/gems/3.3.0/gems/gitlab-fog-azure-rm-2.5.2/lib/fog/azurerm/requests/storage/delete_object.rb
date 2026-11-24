module Fog
  module AzureRM
    class Storage
      # This class provides the actual implementation for service calls.
      class Real
        alias delete_object delete_blob
      end

      # This class provides the mock implementation for unit tests.
      class Mock
        alias delete_object delete_blob
      end
    end
  end
end
