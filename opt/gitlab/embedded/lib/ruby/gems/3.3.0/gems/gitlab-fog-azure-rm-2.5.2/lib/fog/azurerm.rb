require 'azure/core/http/http_error'
require 'erb'
require 'fog/azurerm/config'
require 'fog/azurerm/constants'
require 'fog/azurerm/utilities/general'
require 'fog/azurerm/version'
require 'fog/core'
require 'fog/json'
require 'fog/azurerm/models/storage/sku_name'
require 'fog/azurerm/models/storage/sku_tier'
require 'fog/azurerm/models/storage/kind'
require 'fog/azurerm/identity'

module Fog
  # Main AzureRM fog Provider Module
  module AzureRM
    extend Fog::Provider

    # Autoload Module for Storage
    autoload :Storage, File.expand_path('azurerm/storage', __dir__)

    service(:storage, 'Storage')
  end
end
