module Fog
  module AzureRM
    class Storage
      # This class provides the actual implemention for service calls.
      class Real
        def get_object(...)
          blob, body = get_blob(...)

          blob[:body] = body
          blob
        end
      end

      # This class provides the mock implementation for unit tests.
      class Mock
        def get_object(...)
          blob, body = get_blob(...)

          blob[:body] = body
          blob
        end
      end
    end
  end
end
