# frozen_string_literal: true

module EE
  module API
    module Helpers
      module NotesHelpers
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        class_methods do
          extend ::Gitlab::Utils::Override

          override :noteable_types
          def noteable_types
            super.append(
              ::API::Helpers::NotesHelpers::NoteableType.new(
                noteable_class: ::Epic, feature_category: :portfolio_management, tier: :premium
              ),
              ::API::Helpers::NotesHelpers::NoteableType.new(
                noteable_class: ::Vulnerability, feature_category: :vulnerability_management, tier: :ultimate
              ),
              ::API::Helpers::NotesHelpers::NoteableType.new(
                noteable_class: ::WikiPage::Meta, feature_category: :wiki, noteables_str: 'wiki_pages',
                parent_type: 'group', tier: :premium
              )
            )
          end
        end

        # For vulnerabilities, `NotesFinder#target` returns the
        # `Vulnerabilities::Read` record the noteable was looked up through.
        # Map it back to the `Vulnerability` so that permission checks and the
        # `notes` association used by the endpoints operate on the noteable.
        override :find_noteable
        def find_noteable(noteable_type, noteable_id, parent_type = nil)
          return super unless noteable_type == ::Vulnerability

          params = finder_params_by_noteable_type_and_id(noteable_type, noteable_id, parent_type)
          noteable = ::NotesFinder.new(current_user, params).target&.vulnerability

          noteable = nil unless noteable && can_read_notes?(noteable)
          noteable || not_found!(noteable_type)
        end

        override :add_parent_to_finder_params
        def add_parent_to_finder_params(finder_params, noteable_type, parent_type)
          noteable_name = noteable_type.name.underscore

          if noteable_name == 'epic' || (noteable_name == 'wiki_page/meta' && parent_type == 'group')
            finder_params[:group_id] = user_group.id
          else
            super
          end
        end

        override :present_note_collection
        def present_note_collection(notes, noteable, noteable_class)
          if noteable_is_epic?(noteable_class)
            present_epic_notes(notes, noteable, current_user)
          else
            super
          end
        end

        override :present_single_note
        def present_single_note(note, noteable, noteable_class)
          if noteable_is_epic?(noteable_class)
            present_epic_note(note, noteable, current_user)
          else
            super
          end
        end

        # private projects can be found as long as user is a project member.
        # internal projects can be found by any authenticated user.
        def find_merge_request(merge_request_iid)
          params = finder_params_by_noteable_type_and_id(::MergeRequest, merge_request_iid)

          ::NotesFinder.new(current_user, params).target || not_found!(::MergeRequest)
        end

        private

        def present_epic_notes(notes, noteable, current_user)
          epic = extract_noteable_epic(noteable)
          present notes, with: ::API::Entities::LegacyEpicNote, current_user: current_user, epic: epic
        end

        def present_epic_note(note, noteable, current_user)
          epic = extract_noteable_epic(noteable)
          present note, with: ::API::Entities::LegacyEpicNote, current_user: current_user, epic: epic
        end

        def noteable_is_epic?(noteable_class)
          noteable_class.name == "Epic"
        end

        def extract_noteable_epic(noteable)
          if noteable.is_a?(Epic)
            noteable
          # rubocop:disable Gitlab/NoCodeCoverageComment -- this is part of code that is forward-looking, not testable yet
          elsif noteable.sync_object.present? # :nocov:
            noteable.sync_object # :nocov:
          end
          # rubocop:enable Gitlab/NoCodeCoverageComment
        end
      end
    end
  end
end
