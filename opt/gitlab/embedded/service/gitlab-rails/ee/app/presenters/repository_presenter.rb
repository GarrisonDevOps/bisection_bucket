# frozen_string_literal: true

class RepositoryPresenter < Gitlab::View::Presenter::Delegated
  presents Repository, as: :repository

  def code_owners_path(ref: root_ref)
    return if empty? || (blob = code_owners_blob(ref: ref)).nil?

    Gitlab::Routing.url_helpers.project_blob_path(project, File.join(ref, blob.path))
  end

  def diverged_from_upstream(ref:)
    project.mirror? && project.mirror_ever_updated_successfully? && diverged_from_upstream?(ref)
  end
end
