# This file contains any or all custom Fog errors that we create
module Fog
  module AzureRM
    # This is a custom Fog exception inherited from Azure::Core::Http::HTTPError
    class CustomAzureCoreHttpError < Azure::Core::Http::HTTPError
      def initialize(azure_exception)
        super(azure_exception.http_response)
      end
    end
  end
end
