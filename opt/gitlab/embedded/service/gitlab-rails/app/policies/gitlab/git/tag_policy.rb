# frozen_string_literal: true

module Gitlab
  module Git
    class TagPolicy < BasePolicy
      delegate { project }

      condition(:protected_tag, scope: :subject) do
        ProtectedTag.protected?(project, @subject.name)
      end

      rule { protected_tag & ~can?(:delete_protected_tag) }.prevent :delete_repository_tag

      def project
        @subject.repository.container
      end
    end
  end
end
