# frozen_string_literal: true

module WorkItems
  module EpicAsWorkItem
    module DelegatedAssociationMethods
      def load_target
        proxy_association.target = scope.to_a unless proxy_association.loaded?
        proxy_association.loaded!
        proxy_association.target
      end

      def find(*args)
        return super if block_given?

        scope.find(*args)
      end
    end
  end
end
