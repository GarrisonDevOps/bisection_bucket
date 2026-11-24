# frozen_string_literal: true

module GitlabSubscriptions
  module MemberManagement
    class MemberApprovalPresenter < ::Gitlab::View::Presenter::Delegated
      presents GitlabSubscriptions::MemberManagement::MemberApproval, as: :member_approval

      def human_new_access_level
        ::Gitlab::Access.human_access(new_access_level)
      end

      def human_old_access_level
        ::Gitlab::Access.human_access(old_access_level)
      end

      def source_id
        return member_namespace.project.id if project_namespace?

        member_namespace.id
      end

      def source_name
        member_namespace.name
      end

      def source_web_url
        return member_namespace.project.web_url if project_namespace?

        member_namespace.web_url
      end

      private

      def project_namespace?
        member_namespace.is_a?(::Namespaces::ProjectNamespace)
      end
    end
  end
end
