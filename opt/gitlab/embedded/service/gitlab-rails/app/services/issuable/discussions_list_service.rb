# frozen_string_literal: true

# This service return notes grouped by discussion ID and paginated per discussion.
# System notes also have a discussion ID assigned including Synthetic system notes.
module Issuable
  class DiscussionsListService
    include Gitlab::Utils::StrongMemoize

    attr_reader :current_user, :issuable, :params

    MAX_PER_PAGE = 100

    def initialize(current_user, issuable, params = {})
      @current_user = current_user
      @issuable = issuable
      @params = params.dup
    end

    def execute
      return Note.none unless can_read_issuable_notes?

      notes = NotesFinder.new(current_user, params.merge({ target: issuable, project: issuable.project }))
                .execute.with_web_entity_associations.inc_relations_for_view(issuable).order_created_at_id_asc

      if paginator
        paginated_discussions_by_type = paginator.records.group_by(&:table_name)

        notes = if paginated_discussions_by_type['notes'].present?
                  notes.id_in(paginated_discussions_by_type['notes'].flat_map(&:ids))
                else
                  notes.none
                end
      end

      if include_synthetic_notes? && params[:notes_filter] != UserPreference::NOTES_FILTERS[:only_comments]
        notes = ResourceEvents::MergeIntoNotesService.new(
          issuable, current_user, paginated_notes: paginated_discussions_by_type
        ).execute(notes)
      end

      # Preloading uses the first note's project, though merge request commit notes can belong to another project
      project = notes.first&.project
      notes = ::Preloaders::Projects::NotesPreloader.new(project, current_user).call(notes)

      # Permission check required for:
      # - System notes, which may reference resources the user cannot access
      #   (see Note#all_referenced_mentionables_allowed?)
      # - Notes not attached to the issuable, such as merge request commit notes
      #
      # Other user notes don't need this check because:
      # - If user can access the issuable, they have `read_note` ability on its notes
      # - Internal notes are separately filtered in NotesFinder.redact_internal
      notes = notes.select { |n| readable_note?(n) }

      discussions = Discussion.build_collection(notes, issuable)
      discussions.reverse! if params[:sort] && params[:sort] == :created_desc

      discussions
    end

    def paginator
      strong_memoize(:paginator) do
        per_page = [params[:per_page].to_i, MAX_PER_PAGE].min
        per_page = Kaminari.config.default_per_page if per_page <= 0

        issuable
          .discussion_root_note_ids(
            notes_filter: params[:notes_filter],
            sort: params[:sort],
            include_synthetic_notes: include_synthetic_notes?
          )
          .keyset_paginate(cursor: params[:cursor], per_page: per_page)
      end
    end

    def include_synthetic_notes?
      params.fetch(:include_synthetic_notes, true)
    end

    def can_read_issuable_notes?
      return Ability.allowed?(current_user, :read_security_resource, issuable) if issuable.is_a?(Vulnerability)

      Ability.allowed?(current_user, :"read_#{issuable.to_ability_name}", issuable) &&
        Ability.allowed?(current_user, :read_note, issuable)
    end

    private

    def readable_note?(note)
      return note.system_note_visible_for?(current_user) if note.system?
      return true if note_on_issuable?(note)

      note.readable_by?(current_user)
    end

    # Epics and their work items also list each other's notes (see WorkItems::UnifiedAssociations::NotesExtension).
    def note_on_issuable?(note)
      [issuable, issuable.try(:sync_object)].compact.any? do |noteable|
        note.noteable_id == noteable.id && note.noteable_type == noteable.class.polymorphic_name
      end
    end
  end
end
