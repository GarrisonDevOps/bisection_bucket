# frozen_string_literal: true

module VirtualRegistries
  module Upstreams
    class CheckService < ::VirtualRegistries::Upstreams::CheckBaseService
      include Gitlab::Utils::StrongMemoize

      def check
        return check_local_upstreams_response if check_local_upstreams_response.success? && first_successful_index

        remote_response = check_remote_upstreams

        if first_successful_index
          return remote_response.success? ? remote_response : check_local_upstreams_response
        end

        ERRORS[:file_not_found_on_upstreams]
      end

      private

      def check_local_upstreams_response
        service = ::VirtualRegistries::Upstreams::Local::CheckService.new(upstreams: local_upstreams, params: params)

        response = service.execute
        local_upstreams.each { |u| store_result(u, false) }
        store_result(response[:upstream], true) if response.success?

        response
      end
      strong_memoize_attr :check_local_upstreams_response

      def check_remote_upstreams
        range = Range.new(nil, results.index(true) || (results.size - 1))
        remote_upstreams = upstreams[range].select(&:remote?)

        service = ::VirtualRegistries::Upstreams::Remote::CheckService.new(upstreams: remote_upstreams, params: params)

        response = service.execute
        remote_upstreams.each { |u| store_result(u, false) }
        store_result(response[:upstream], true) if response.success?

        response
      end

      def store_result(upstream, result)
        results[upstreams.find_index(upstream)] = result
      end

      def local_upstreams
        upstreams.select(&:local?)
      end
      strong_memoize_attr :local_upstreams

      def path
        params[:path]
      end
    end
  end
end
