module Fog
  module AzureRM
    # This filter prevents Net::HTTP from inflating compressed response bodies
    class IdentityEncodingFilter
      def call(request, next_filter)
        request.headers['Accept-Encoding'] ||= 'identity'

        next_filter.call
      end
    end
  end
end
