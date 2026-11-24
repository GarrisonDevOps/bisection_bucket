# frozen_string_literal: true

module EE
  module API
    module Invitations
      extend ActiveSupport::Concern

      prepended do
        helpers do
          params :invitation_params_ee do
            optional :member_role_id, type: Integer, desc: 'ID of a member role to assign to the invited user. ' \
                                                       'Ultimate only.'
          end
        end
      end
    end
  end
end
