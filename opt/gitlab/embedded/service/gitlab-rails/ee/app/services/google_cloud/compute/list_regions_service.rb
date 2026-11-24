# frozen_string_literal: true

module GoogleCloud
  module Compute
    class ListRegionsService < ::GoogleCloud::Compute::BaseService
      private

      def call_client
        regions = client.regions(filter: filter, max_results: max_results, page_token: page_token, order_by: order_by)
        ServiceResponse.success(payload: {
          items: regions.items.map { |r| { name: r.name, description: r.description } },
          next_page_token: regions.next_page_token
        })
      end
    end
  end
end
