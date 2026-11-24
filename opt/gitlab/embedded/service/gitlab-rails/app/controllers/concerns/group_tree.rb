# frozen_string_literal: true

module GroupTree
  include Gitlab::Utils::StrongMemoize

  # rubocop:disable Gitlab/ModuleWithInstanceVariables
  def render_group_tree(groups)
    groups = groups.sort_by_attribute(@sort = safe_params[:sort])

    if search_descendants?
      pagination_resource = filtered_groups(groups)
      @groups = groups_with_ancestors(pagination_resource.map(&:id))
    elsif safe_params[:parent_id].present?
      @groups = subgroups(groups)
    else
      @groups = root_groups(groups)
    end

    respond_to do |format|
      format.html
      format.json do
        serializer = GroupChildSerializer.new(current_user: current_user)
                       .with_pagination(request, response)

        serializer.expand_hierarchy if search_descendants?

        render json: serializer.represent(@groups, {
          upto_preloaded_ancestors_only: inactive?,
          pagination_resource: pagination_resource
        })
      end
    end
    # rubocop:enable Gitlab/ModuleWithInstanceVariables
  end

  private

  # rubocop: disable CodeReuse/ActiveRecord -- requires specialized queries
  def subgroups(groups)
    query = groups.where(parent_id: safe_params[:parent_id]).with_selects_for_list
    paginate(query)
  end

  def root_groups(groups)
    query = groups.by_parent(nil).with_selects_for_list
    paginate(query)
  end

  # group_tree_finder already pushed the filter into the finder on the advanced path,
  # so searching the relation again here would be redundant.
  def filtered_groups(groups)
    return paginate(groups) if advanced_group_tree_finder?

    paginate(groups.search(safe_params[:filter]))
  end

  def groups_with_ancestors(group_ids)
    # Find ancestors by ID so the search filters do not apply to them and they get preloaded.
    # Paginate before this so pagination does not cut off ancestors.
    ancestors = Group.where(id: group_ids).self_and_ancestors
    ancestors = ancestors.self_or_ancestors_inactive if inactive?
    ancestors.with_selects_for_list
  end
  # rubocop: enable CodeReuse/ActiveRecord

  def paginate(group)
    return group.page(safe_params[:page]).per(per_page) unless keyset_pagination?

    group.keyset_paginate(cursor: safe_params[:cursor], per_page: per_page)
  end

  def per_page
    Kaminari.config.default_per_page
  end

  def inactive?
    safe_params[:active] == false
  end

  def keyset_pagination?
    safe_params[:pagination] == 'keyset'
  end

  def search_descendants?
    safe_params[:filter].present? || inactive?
  end

  # With the flag off the legacy finder is called with exactly the params it got before,
  # so the flag-off path stays the old behaviour. search_include_parents: false keeps
  # matching a group's own path and name rather than widening to full paths.
  def group_tree_finder(finder_params)
    return ::GroupsFinder.new(current_user, finder_params) unless advanced_group_tree_finder?

    ::Namespaces::GroupsFinder.new(
      current_user,
      finder_params.merge(search: safe_params[:filter], search_include_parents: false)
    )
  end

  # namespaces_advanced_groups_finder is already fully enabled, so it cannot roll this
  # out gradually. group_children_advanced_finder is what makes that possible.
  def advanced_group_tree_finder?
    ::Feature.enabled?(:namespaces_advanced_groups_finder, current_user) &&
      ::Feature.enabled?(:group_children_advanced_finder, current_user)
  end

  def safe_params
    filters = group_tree_filters
    filters.merge(
      active: Gitlab::Utils.to_boolean(filters[:active]),
      archived: Gitlab::Utils.to_boolean(filters[:archived], default: filters[:archived])
    )
  end
  strong_memoize_attr :safe_params

  def group_tree_filters
    params.permit(:sort, :filter, :parent_id, :page, :archived, :active, :cursor, :pagination)
  end
end
