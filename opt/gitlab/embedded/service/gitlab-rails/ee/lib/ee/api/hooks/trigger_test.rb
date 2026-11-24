# frozen_string_literal: true

module EE
  module API
    module Hooks
      module TriggerTest
        extend ActiveSupport::Concern

        prepended do
          helpers do
            def hook_test_service(hook, entity)
              return super unless entity == GroupHook

              TestHooks::GroupService.new(hook, current_user, params[:trigger])
            end
          end
        end
      end
    end
  end
end
