# frozen_string_literal: true

class AuditEventEntity < Grape::Entity
  alias_method :audit_event, :object

  expose :id
  expose :author do |_|
    {
      name: presenter.author_name,
      url: presenter.author_url,
      removed: presenter.author_removed?
    }
  end

  expose :action do |_|
    presenter.action
  end

  expose :date do |_|
    presenter.date
  end

  expose :ip_address do |_|
    presenter.ip_address
  end

  expose :object do |_|
    {
      name: presenter.object,
      url: presenter.object_url
    }
  end

  expose :target do |_|
    presenter.target
  end

  expose :details do |_|
    presenter.details
  end

  private

  def presenter
    @presenter ||= audit_event.present
  end
end
