# frozen_string_literal: true

module VirtualRegistries
  module Cache
    class EntriesFinder
      def initialize(upstream:, params: {})
        @upstream = upstream
        @params = params
      end

      def execute
        upstream
          .default_cache_entries
          .order_created_desc
          .search_by_relative_path(params[:search])
      end

      private

      attr_reader :upstream, :params
    end
  end
end
