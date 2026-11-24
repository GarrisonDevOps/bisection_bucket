# frozen_string_literal: true

module EE
  module API
    module Helpers
      module UsersHelpers
        extend ActiveSupport::Concern

        prepended do
          params :optional_params_ee do
            optional :shared_runners_minutes_limit, type: Integer, desc: 'Maximum number of monthly compute minutes for this user. `nil` inherits the instance default, `0` means unlimited, and a value greater than `0` sets the limit. Can be set by administrators only. Premium and Ultimate only.'
            optional :extra_shared_runners_minutes_limit, type: Integer, desc: '(admin-only) Extra compute minutes quota for this user. Premium and Ultimate only.'
            optional :group_id_for_saml, type: Integer, desc: 'ID for group where SAML has been configured'
            optional :auditor, type: Grape::API::Boolean, desc: 'Flag indicating auditor status of the user. Default is `false` for new users. Premium and Ultimate only.'
          end

          params :optional_index_params_ee do
            optional :skip_ldap, type: Grape::API::Boolean, default: false, desc: 'If `true`, excludes LDAP users from the results.'
            optional :auditors, type: Grape::API::Boolean, default: false, desc: 'If `true`, returns only auditor users. Premium and Ultimate only.'
          end
        end
      end
    end
  end
end
