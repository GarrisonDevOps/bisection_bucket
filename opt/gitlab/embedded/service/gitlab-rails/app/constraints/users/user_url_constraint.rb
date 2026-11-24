# frozen_string_literal: true

module Users
  class UserUrlConstraint
    def matches?(request, existence_check: true)
      full_path = request.params[:username]

      return false unless NamespacePathValidator.valid_path?(full_path)
      return true unless existence_check

      User.find_by_full_path(full_path, follow_redirects: request.get?).present?
    end
  end
end
