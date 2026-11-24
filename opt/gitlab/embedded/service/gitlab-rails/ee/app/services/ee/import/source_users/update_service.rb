# frozen_string_literal: true

module EE
  module Import
    module SourceUsers
      module UpdateService
        extend ::Gitlab::Utils::Override

        override :update_params
        def update_params
          params = super

          params.merge(force_name_change: true)
        end
      end
    end
  end
end
