# frozen_string_literal: true

module VirtualRegistries
  class UpstreamsFinder
    def initialize(upstream_class:, group:, params: {})
      @group = group
      @params = params
      @upstream_class = upstream_class
    end

    def execute
      upstreams = upstream_class.for_group(group)

      upstreams = filter_by_upstream_name(upstreams) if params[:upstream_name].present?

      upstreams
    end

    private

    attr_reader :group, :params, :upstream_class

    def filter_by_upstream_name(upstreams)
      upstreams.search_by_name(params[:upstream_name])
    end
  end
end
