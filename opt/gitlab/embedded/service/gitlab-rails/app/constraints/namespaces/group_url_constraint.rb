# frozen_string_literal: true

module Namespaces
  class GroupUrlConstraint
    def matches?(request, existence_check: true)
      # API requests are checked against these routes first, and `params` also includes query and body values
      # such as a numeric `group_id`, so only the route's own segments can name the group.
      full_path = request.path_parameters[:group_id] || request.path_parameters[:id]

      return false unless NamespacePathValidator.valid_path?(full_path)
      return true unless existence_check

      Group.find_by_full_path(full_path, follow_redirects: request.get?).present?
    end
  end
end
