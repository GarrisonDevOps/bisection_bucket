# frozen_string_literal: true

module Ai
  module ModelSelection
    module SelectionApplicable
      extend ActiveSupport::Concern

      def current_user
        raise NotImplementedError, "#current_user method must be implement in #{self.class.name}"
      end

      included do
        include Gitlab::Utils::StrongMemoize

        def duo_default_namespace_with_fallback
          current_user.user_preference.duo_default_namespace_with_fallback
        end
        strong_memoize_attr :duo_default_namespace_with_fallback

        def default_duo_namespace_required?
          # we need to return the default namespace only when there is multiple seats assigned to the user.
          # Otherwise, we might have error in undesirable cases
          # e.g. when self-hosted feature setting are not correctly set
          return false if duo_default_namespace_with_fallback

          # if any of the assigned seat has a namespace with model switching enable
          # it is required for the user to have a default namespace to be selected.
          # This logic is in EE::GlobalPolicy#can_assign_default_duo_group?
          Ability.allowed?(current_user, :assign_default_duo_group)
        end
      end
    end
  end
end
