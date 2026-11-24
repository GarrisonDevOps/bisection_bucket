# frozen_string_literal: true

class NoteDiffFile < ApplicationRecord
  include DiffFile
  include Gitlab::EncodingHelper
  include Importable
  include Notes::WithAssociatedNote

  # Looks the notes up by `commit_id` first, in a materialized CTE, and filters on project and type
  # afterwards. Filtering on `project_id` in the same query lets the planner pick a bitmap scan of
  # `index_notes_on_project_id_and_noteable_type`, whose cost grows with the project's note count.
  scope :referencing_sha, ->(oids, project_id:) do
    notes = Note.where(commit_id: oids).select(:id, :project_id, :type)
    candidate_notes = Gitlab::SQL::CTE.new(:candidate_notes, notes)

    with(candidate_notes.to_arel)
      .joins('INNER JOIN candidate_notes ON candidate_notes.id = note_diff_files.diff_note_id')
      .where(candidate_notes: { project_id: project_id, type: DiffNote.sti_name })
  end

  # Remove together with the bound_repository_cleanup_transactions feature flag.
  # https://gitlab.com/gitlab-org/gitlab/-/work_items/638388
  scope :legacy_referencing_sha, ->(oids, project_id:) do
    joins(:diff_note).where(notes: { project_id: project_id, commit_id: oids })
  end

  delegate :original_position, :project, :resolved_at, to: :diff_note

  belongs_to :diff_note, inverse_of: :note_diff_file

  validates :diff_note, presence: true

  def raw_diff_file
    return unless original_position

    raw_diff = Gitlab::Git::Diff.new(to_hash)

    Gitlab::Diff::File.new(
      raw_diff,
      repository: project.repository,
      diff_refs: original_position.diff_refs,
      unique_identifier: id
    )
  end

  def diff_export
    force_encode_utf8(diff)
  rescue ArgumentError
    diff
  end

  private

  def skip_namespace_validation?
    importing?
  end

  def note_namespace_id
    diff_note&.namespace_id || diff_note&.project&.project_namespace_id
  end
end
