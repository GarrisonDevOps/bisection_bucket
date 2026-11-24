# frozen_string_literal: true

module Geo
  class PrimaryApiRequestService < RequestService
    include Gitlab::Geo::LogHelpers

    attr_reader :api_path, :method

    def initialize(api_path, method)
      @api_path = api_path
      @method = method
    end

    def execute
      super(api_url, nil, method: method, with_response: true)
    end

    def api_url
      ::Gitlab::Geo.primary_node.api_url(api_path)
    end
  end
end
