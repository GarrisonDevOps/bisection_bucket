# frozen_string_literal: true

require 'active_support'
require 'active_support/time'

module Gitlab
  module CloudConnector
    autoload(:JsonWebToken, 'gitlab/cloud_connector/json_web_token')
    autoload(:Configuration, 'gitlab/cloud_connector/configuration')
    autoload(:DataModel, 'gitlab/cloud_connector/data_model')
    autoload(:AvailableServicesGenerator, 'gitlab/cloud_connector/available_services_generator')
  end
end
