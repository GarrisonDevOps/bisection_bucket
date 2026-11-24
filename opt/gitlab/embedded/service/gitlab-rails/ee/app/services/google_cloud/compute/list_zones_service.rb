# frozen_string_literal: true

module GoogleCloud
  module Compute
    class ListZonesService < ::GoogleCloud::Compute::BaseService
      private

      def call_client
        zones = client.zones(filter: filter, max_results: max_results, page_token: page_token, order_by: order_by)
        ServiceResponse.success(payload: {
          items: zones.items.map { |z| { name: z.name, description: z.description } },
          next_page_token: zones.next_page_token
        })
      end
    end
  end
end
