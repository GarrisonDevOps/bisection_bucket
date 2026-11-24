# frozen_string_literal: true

class GeoNodeFinder
  include Gitlab::Allowable

  def initialize(current_user, params = {})
    @current_user = current_user
    @params = params
  end

  def execute
    return GeoNode.none unless can?(current_user, :read_all_geo)

    geo_nodes = init_collection

    geo_nodes = by_id(geo_nodes)
    geo_nodes = by_name(geo_nodes)

    geo_nodes.ordered
  end

  private

  attr_reader :current_user, :params

  def init_collection
    GeoNode.all
  end

  def by_id(geo_nodes)
    return geo_nodes unless params[:ids]

    geo_nodes.id_in(params[:ids])
  end

  # A Geo node's name defaults to its URL, so a requested name may differ
  # from the stored name only by a trailing slash. Only names without an
  # exact match fall back to slash variants, so nodes whose names differ
  # only by a trailing slash (e.g. 'gdk' and 'gdk/') each resolve exactly.
  def by_name(geo_nodes)
    return geo_nodes unless params[:names]

    names = params[:names]
    matched_names = geo_nodes.name_in(names).select(:name).map(&:name)
    unmatched_names = names - matched_names

    return geo_nodes.name_in(names) if unmatched_names.empty?

    sanitized_names = unmatched_names.flat_map do |name|
      sanitizer = Geo::NodeNameSanitizer.new(name: name)

      [sanitizer.name_with_slash, sanitizer.name_without_slash]
    end.uniq

    geo_nodes.name_in((names + sanitized_names).uniq)
  end
end
