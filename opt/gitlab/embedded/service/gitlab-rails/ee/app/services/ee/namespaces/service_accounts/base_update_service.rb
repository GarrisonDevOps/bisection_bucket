# frozen_string_literal: true

module EE
  module Namespaces
    module ServiceAccounts
      module BaseUpdateService
        extend ::Gitlab::Utils::Override

        private

        override :skip_confirmation?
        def skip_confirmation?
          return true if super

          root_namespace.is_a?(::Group) && root_namespace.owner_of_email?(params[:email])
        end
      end
    end
  end
end
