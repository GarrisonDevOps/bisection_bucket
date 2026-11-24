# frozen_string_literal: true

module EE
  module Gitlab
    module SnippetSearchResults
      extend ::Gitlab::Utils::Override

      # Special scope for .com
      # https://gitlab.com/gitlab-org/gitlab/issues/26123
      override :finder_params
      def finder_params
        params = super
        return params unless ::Gitlab.com?

        params.merge(authorized_and_user_personal: true)
      end
    end
  end
end
