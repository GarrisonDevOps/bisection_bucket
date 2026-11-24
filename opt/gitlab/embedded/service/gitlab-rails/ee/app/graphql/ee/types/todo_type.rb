# frozen_string_literal: true

module EE
  module Types
    module TodoType # rubocop:disable Gitlab/BoundedContexts -- EE extension of the CE TodoType
      extend ActiveSupport::Concern
      include ::Gitlab::Utils::StrongMemoize

      # A to-do can be readable while its target is not, when the target sits
      # behind an expired but restorable SAML session (see EE::TodoPolicy). The
      # to-do is listed so the UI can prompt reauthentication, but its
      # target-derived contents must stay hidden until the session is restored.
      def body
        target_hidden? ? '' : object.body
      end

      def author
        return super unless target_hidden?

        resource = object.project || object.group
        ::Users::Internal.in_organization(resource.organization_id).ghost
      end

      def note
        return if target_hidden?

        object.note
      end

      private

      def target_hidden?
        !object.target&.readable_by?(current_user)
      end
      strong_memoize_attr :target_hidden?
    end
  end
end
