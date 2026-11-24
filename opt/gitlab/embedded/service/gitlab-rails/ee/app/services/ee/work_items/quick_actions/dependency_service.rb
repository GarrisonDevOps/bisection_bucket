# frozen_string_literal: true

module EE
  module WorkItems
    module QuickActions
      module DependencyService
        extend ::Gitlab::Utils::Override

        override :parse_params
        def parse_params(items)
          super + build_extractor(items).references(:epic).map(&:work_item) # rubocop:disable CodeReuse/ActiveRecord -- reference extraction requires AR queries
        end
      end
    end
  end
end
