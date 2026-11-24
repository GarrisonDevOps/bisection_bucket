module Fog
  module AzureRM
    class Storage
      # This class provides the actual implementation for service calls.
      # This is to make this library compatible with CarrierWave.
      class Real
        def copy_object(source_container, source_blob, target_container, target_blob, options = {})
          copy_blob(target_container, target_blob, source_container, source_blob, options)
        end
      end

      # This class provides the mock implementation for unit tests.
      class Mock
        def copy_object(*args)
          copy_blob(*args)
        end
      end
    end
  end
end
