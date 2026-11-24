# frozen_string_literal: true

module Geo
  class NodeUpdateService
    attr_reader :geo_node, :params

    def initialize(geo_node, params)
      @geo_node = geo_node
      @params = params.dup
      @params[:namespace_ids] = @params[:namespace_ids].to_s.split(',') if @params[:namespace_ids].is_a? String
      @params[:organization_ids] = @params[:organization_ids].to_s.split(',') if @params[:organization_ids].is_a? String
    end

    def execute
      return false unless geo_node.update(params)

      true
    end
  end
end
