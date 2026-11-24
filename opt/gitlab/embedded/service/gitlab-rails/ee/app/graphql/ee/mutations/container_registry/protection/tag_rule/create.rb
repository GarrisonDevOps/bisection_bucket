# frozen_string_literal: true

module EE
  module Mutations
    module ContainerRegistry
      module Protection
        module TagRule
          module Create
            extend ActiveSupport::Concern

            prepended do
              arguments.values_at('minimumAccessLevelForDelete', 'minimumAccessLevelForPush').each do |arg|
                arg.instance_variable_set(:@null, true)
              end
            end
          end
        end
      end
    end
  end
end
