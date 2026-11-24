# frozen_string_literal: true

module EE
  module Gitlab
    module Graphql
      module Queries
        extend ActiveSupport::Concern

        module Fragments
          HOME_EE = %r{^(ee|ee_else_ce)/}

          def resolve(import_path, file)
            frag_path = import_path.gsub(HOME_EE, "#{root / 'ee' / dir}/")
            super(frag_path, file)
          end
        end

        class_methods do
          def all
            super + find(Rails.root / 'ee/app/assets/javascripts') + find(Rails.root / 'ee/app/graphql/queries')
          end
        end
      end
    end
  end
end
