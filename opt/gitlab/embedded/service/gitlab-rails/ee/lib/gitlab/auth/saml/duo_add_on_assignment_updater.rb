# frozen_string_literal: true

module Gitlab
  module Auth
    module Saml
      class DuoAddOnAssignmentUpdater
        include Gitlab::Utils::StrongMemoize

        attr_reader :user, :auth_hash

        def initialize(user, auth_hash)
          @user = user
          @auth_hash = auth_hash
        end

        def execute
          return unless preconditions_met?
          return unless add_on_purchase&.active?

          if user_in_add_on_group?
            assign_duo_seat
          else
            unassign_duo_seat
          end
        end

        private

        def preconditions_met?
          duo_groups.present?
        end

        def saml_config
          Gitlab::Auth::Saml::Config.new(auth_hash.provider)
        end

        def assign_duo_seat
          return if existing_add_on_assignment?

          ::GitlabSubscriptions::AddOnPurchases::CreateUserAddOnAssignmentWorker.perform_async(user.id)
        end

        def unassign_duo_seat
          return unless existing_add_on_assignment?

          ::GitlabSubscriptions::AddOnPurchases::DestroyUserAddOnAssignmentWorker.perform_async(user.id)
        end

        def group_names_from_saml
          auth_hash.groups
        end
        strong_memoize_attr :group_names_from_saml

        def duo_groups
          saml_config.duo_add_on_groups
        end

        def user_in_add_on_group?
          (group_names_from_saml & duo_groups).any?
        end

        def add_on_purchase
          ::GitlabSubscriptions::Duo.enterprise_or_pro_for_namespace(nil)
        end
        strong_memoize_attr :add_on_purchase

        def existing_add_on_assignment?
          user.assigned_add_ons.for_active_add_on_purchase_ids(add_on_purchase.id).any?
        end
        strong_memoize_attr :existing_add_on_assignment?
      end
    end
  end
end
