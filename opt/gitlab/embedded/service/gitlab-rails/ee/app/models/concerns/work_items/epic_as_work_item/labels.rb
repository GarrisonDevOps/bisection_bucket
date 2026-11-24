# frozen_string_literal: true

module WorkItems
  module EpicAsWorkItem
    module Labels
      extend ActiveSupport::Concern

      included do
        has_many :label_links, as: :target, inverse_of: :target do
          include DelegatedAssociationMethods

          def scope
            proxy_association.owner.work_item&.label_links || LabelLink.none
          end
        end

        has_many :labels, through: :label_links do
          include DelegatedAssociationMethods

          def scope
            proxy_association.owner.work_item&.labels || Label.none
          end

          def <<(*records)
            return self unless proxy_association.owner.work_item

            proxy_association.owner.work_item.labels << records.flatten
            proxy_association.reset
            self
          end
        end

        def label_ids
          work_item&.label_ids || []
        end
      end
    end
  end
end
