# frozen_string_literal: true

module EE
  module Mutations
    module Ci
      module Runner
        module Update
          extend ActiveSupport::Concern

          prepended do
            # rubocop:disable Cop/InjectEnterpriseEditionModule -- This is not a typical EE module include
            # that happens from the non-EE code part. It's a "standard" include of an EE module inside
            # other EE module
            include EE::Mutations::Ci::Runner::CommonMutationArguments
            # rubocop:enable Cop/InjectEnterpriseEditionModule
          end
        end
      end
    end
  end
end
