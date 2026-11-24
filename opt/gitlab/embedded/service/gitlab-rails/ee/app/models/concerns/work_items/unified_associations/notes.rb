# frozen_string_literal: true

module WorkItems
  module UnifiedAssociations
    module Notes
      extend ActiveSupport::Concern

      included do
        has_many :own_notes, class_name: 'Note', as: :noteable, inverse_of: :noteable
        # rubocop:disable Cop/ActiveRecordDependent -- needed because this is a polymorphic association
        has_many :notes, -> {
          extending ::Notes::ParticipantAssociationsExtension, ::WorkItems::UnifiedAssociations::NotesExtension
        }, inverse_of: :noteable, as: :noteable, dependent: :destroy
        # rubocop:enable Cop/ActiveRecordDependent

        has_many :note_authors, -> { distinct }, through: :notes, source: :author
        has_many :user_note_authors, -> { distinct.where("notes.system = false") }, through: :notes, source: :author
      end
    end
  end
end
